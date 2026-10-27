package com.github.okulyk.mev.jito;

import auth.Auth;
import auth.AuthServiceGrpc;
import bundle.BundleOuterClass.Bundle;
import bundle.BundleOuterClass.BundleResult;
import com.google.protobuf.ByteString;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ClientInterceptors;
import io.grpc.ForwardingClientCall;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.stub.StreamObserver;
import io.quarkus.scheduler.Scheduled;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import packet.PacketOuterClass.Meta;
import packet.PacketOuterClass.Packet;
import searcher.Searcher.SendBundleRequest;
import searcher.Searcher.SubscribeBundleResultsRequest;
import searcher.SearcherServiceGrpc;

@ApplicationScoped
public class JitoSearcher {

    public enum Fate { PENDING, LANDED, REJECTED, DROPPED }

    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final Metadata.Key<String> AUTHORIZATION =
            Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

    @ConfigProperty(name = "searcher.block-engine")
    String blockEngine;

    @ConfigProperty(name = "searcher.seed-base64")
    String seedBase64;

    private final Map<String, Fate> outcomes = new ConcurrentHashMap<>();
    private final AtomicBoolean streaming = new AtomicBoolean();
    private volatile String accessToken = "";
    private volatile String refreshToken = "";
    private ManagedChannel channel;
    private Ed25519PrivateKeyParameters key;
    private byte[] pubkey;
    private AuthServiceGrpc.AuthServiceBlockingStub authStub;
    private SearcherServiceGrpc.SearcherServiceBlockingStub searcherStub;
    private SearcherServiceGrpc.SearcherServiceStub searcherAsync;

    @PostConstruct
    void init() {
        key = new Ed25519PrivateKeyParameters(Base64.getDecoder().decode(seedBase64), 0);
        pubkey = key.generatePublicKey().getEncoded();
        channel = ManagedChannelBuilder.forTarget(blockEngine).useTransportSecurity().build();
        authStub = AuthServiceGrpc.newBlockingStub(channel);
        Channel authed = ClientInterceptors.intercept(channel, new BearerInterceptor());
        searcherStub = SearcherServiceGrpc.newBlockingStub(authed);
        searcherAsync = SearcherServiceGrpc.newStub(authed);
        login();
        subscribeResults();
    }

    private void login() {
        String challenge = authStub.generateAuthChallenge(
                        Auth.GenerateAuthChallengeRequest.newBuilder()
                                .setRole(Auth.Role.SEARCHER)
                                .setPubkey(ByteString.copyFrom(pubkey))
                                .build())
                .getChallenge();
        String payload = base58(pubkey) + "-" + challenge;
        byte[] message = payload.getBytes(StandardCharsets.UTF_8);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, key);
        signer.update(message, 0, message.length);
        Auth.GenerateAuthTokensResponse tokens = authStub.generateAuthTokens(
                Auth.GenerateAuthTokensRequest.newBuilder()
                        .setChallenge(payload)
                        .setClientPubkey(ByteString.copyFrom(pubkey))
                        .setSignedChallenge(ByteString.copyFrom(signer.generateSignature()))
                        .build());
        refreshToken = tokens.getRefreshToken().getValue();
        accessToken = tokens.getAccessToken().getValue();
    }

    @Scheduled(every = "{searcher.refresh-every:2m}")
    void refresh() {
        try {
            accessToken = authStub.refreshAccessToken(
                            Auth.RefreshAccessTokenRequest.newBuilder().setRefreshToken(refreshToken).build())
                    .getAccessToken().getValue();
        } catch (RuntimeException e) {
            login();
        }
        subscribeResults();
    }

    public String send(List<byte[]> signedTxs) {
        Bundle.Builder bundle = Bundle.newBuilder();
        for (byte[] tx : signedTxs) {
            bundle.addPackets(Packet.newBuilder()
                    .setData(ByteString.copyFrom(tx))
                    .setMeta(Meta.newBuilder().setSize(tx.length))
                    .build());
        }
        String uuid = searcherStub.withDeadlineAfter(5, TimeUnit.SECONDS)
                .sendBundle(SendBundleRequest.newBuilder().setBundle(bundle).build())
                .getUuid();
        outcomes.put(uuid, Fate.PENDING);
        return uuid;
    }

    private void subscribeResults() {
        if (!streaming.compareAndSet(false, true)) {
            return;
        }
        searcherAsync.subscribeBundleResults(SubscribeBundleResultsRequest.getDefaultInstance(),
                new StreamObserver<BundleResult>() {
                    @Override
                    public void onNext(BundleResult result) {
                        Fate next = switch (result.getResultCase()) {
                            case FINALIZED, PROCESSED -> Fate.LANDED;
                            case REJECTED -> Fate.REJECTED;
                            case DROPPED -> Fate.DROPPED;
                            default -> null;
                        };
                        if (next != null) {
                            outcomes.computeIfPresent(result.getBundleId(), (id, old) -> next);
                        }
                    }

                    @Override
                    public void onError(Throwable t) {
                        streaming.set(false);
                    }

                    @Override
                    public void onCompleted() {
                        streaming.set(false);
                    }
                });
    }

    public double landRate() {
        long landed = outcomes.values().stream().filter(o -> o == Fate.LANDED).count();
        long sent = outcomes.size();
        return sent == 0 ? 0.0 : (double) landed / sent;
    }

    public Map<String, Fate> outcomes() {
        return Map.copyOf(outcomes);
    }

    private final class BearerInterceptor implements ClientInterceptor {
        @Override
        public <Q, R> ClientCall<Q, R> interceptCall(MethodDescriptor<Q, R> method, CallOptions options, Channel next) {
            return new ForwardingClientCall.SimpleForwardingClientCall<>(next.newCall(method, options)) {
                @Override
                public void start(Listener<R> listener, Metadata headers) {
                    headers.put(AUTHORIZATION, "Bearer " + accessToken);
                    super.start(listener, headers);
                }
            };
        }
    }

    static String base58(byte[] in) {
        BigInteger n = new BigInteger(1, in);
        StringBuilder sb = new StringBuilder();
        BigInteger base = BigInteger.valueOf(58);
        for (; n.signum() > 0; n = n.divide(base)) {
            sb.append(ALPHABET.charAt(n.mod(base).intValue()));
        }
        for (int i = 0; i < in.length && in[i] == 0; i++) {
            sb.append('1');
        }
        return sb.reverse().toString();
    }
}
