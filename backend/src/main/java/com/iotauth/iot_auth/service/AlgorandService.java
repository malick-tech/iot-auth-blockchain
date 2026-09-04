package com.iotauth.iot_auth.service;

import com.algorand.algosdk.account.Account;
import com.algorand.algosdk.transaction.AppBoxReference;
import com.algorand.algosdk.transaction.SignedTransaction;
import com.algorand.algosdk.transaction.Transaction;
import com.algorand.algosdk.util.Encoder;
import com.algorand.algosdk.v2.client.common.AlgodClient;
import com.algorand.algosdk.v2.client.common.Response;
import com.algorand.algosdk.v2.client.model.Box;
import com.algorand.algosdk.v2.client.model.NodeStatusResponse;
import com.algorand.algosdk.v2.client.model.PendingTransactionResponse;
import com.algorand.algosdk.v2.client.model.PostTransactionsResponse;
import com.algorand.algosdk.v2.client.model.TransactionParametersResponse;
import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.EventType;
import com.iotauth.iot_auth.util.CryptoUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AlgorandService {

    private static final byte DID_STATUS_UPLOADING = 0;
    private static final byte DID_STATUS_READY = 1;
    private static final byte DID_STATUS_DELETED = 2;
    private static final int METADATA_LENGTH = 25;
    private static final int STATUS_OFFSET = 16;

    private final AlgodClient algodClient;
    private final Account algorandAdminAccount;
    private final AuditLogService auditLogService;

    @Value("${iot.auth.algorand.app-id}")
    private long appId;

    /**
     * Publie un DID Document selon la methode officielle did:algo app namespace.
     *
     * Metadata box:
     * - key   = public key Ed25519 brute du sujet (32 octets)
     * - value = ARC4 tuple (uint64,uint64,uint8,uint64)
     *
     * Data box:
     * - key   = uint64 derive de la cle publique
     * - value = DID Document JSON UTF-8
     */
    public String publishDidDocument(String did, String publicKey, String metadata) {
        byte[] subjectKey = CryptoUtils.decodeBase32(publicKey);
        byte[] dataBoxKey = CryptoUtils.deriveDidDataBoxKey(subjectKey);
        return callPublishDid(subjectKey, dataBoxKey, metadata.getBytes(StandardCharsets.UTF_8), did);
    }

    /**
     * Met a jour le status resolvable de la metadata box did:algo.
     * ACTIVE => 1 (ready), REVOKED => 2 (deleted / non resolvable).
     */
    public String publishDeviceLifecycleEvent(String did, String status, String reason) {
        byte[] subjectKey = CryptoUtils.extractDidSubjectPublicKey(did);
        byte statusCode = "REVOKED".equalsIgnoreCase(status) ? DID_STATUS_DELETED : DID_STATUS_READY;
        return callUpdateStatus(subjectKey, statusCode, did);
    }

    /**
     * Compatibilite avec les services existants:
     * - prefix "doc:" lit le DID Document depuis la data box did:algo
     * - prefix "st:" retourne ACTIVE / REVOKED depuis le status de la metadata box
     */
    public Optional<byte[]> readBox(String prefix, String did) {
        try {
            byte[] subjectKey = CryptoUtils.extractDidSubjectPublicKey(did);
            byte[] metadata = readRawBox(subjectKey).orElse(null);
            if (metadata == null || metadata.length < METADATA_LENGTH) {
                return Optional.empty();
            }

            byte status = metadata[STATUS_OFFSET];
            if ("st:".equals(prefix)) {
                return Optional.of(statusToLifecycle(status).getBytes(StandardCharsets.UTF_8));
            }

            if ("doc:".equals(prefix)) {
                if (status != DID_STATUS_READY) {
                    return Optional.empty();
                }
                byte[] startDataBoxKey = Arrays.copyOfRange(metadata, 0, 8);
                byte[] endDataBoxKey = Arrays.copyOfRange(metadata, 8, 16);
                if (!Arrays.equals(startDataBoxKey, endDataBoxKey)) {
                    log.warn("DID Document fragmente non supporte par ce prototype pour did={}", did);
                    return Optional.empty();
                }
                byte[] document = readRawBox(startDataBoxKey).orElse(null);
                if (document == null) {
                    return Optional.empty();
                }
                int finalLength = (int) readUint64(metadata, 17);
                return Optional.of(Arrays.copyOf(document, Math.min(finalLength, document.length)));
            }

            return Optional.empty();
        } catch (Exception e) {
            log.warn("Lecture did:algo impossible pour prefix='{}', did={}: {}", prefix, did, e.getMessage());
            return Optional.empty();
        }
    }

    private String callPublishDid(byte[] subjectKey, byte[] dataBoxKey, byte[] document, String didForLogs) {
        List<byte[]> appArgs = new ArrayList<>();
        appArgs.add("PUBLISH_DID".getBytes(StandardCharsets.UTF_8));
        appArgs.add(subjectKey);
        appArgs.add(dataBoxKey);
        appArgs.add(document);

        List<AppBoxReference> boxes = new ArrayList<>();
        boxes.add(new AppBoxReference(0, subjectKey));
        boxes.add(new AppBoxReference(0, dataBoxKey));

        return submitApplicationCall("PUBLISH_DID", appArgs, boxes, didForLogs);
    }

    private String callUpdateStatus(byte[] subjectKey, byte statusCode, String didForLogs) {
        List<byte[]> appArgs = new ArrayList<>();
        appArgs.add("UPDATE_STATUS".getBytes(StandardCharsets.UTF_8));
        appArgs.add(subjectKey);
        appArgs.add(new byte[]{statusCode});

        List<AppBoxReference> boxes = new ArrayList<>();
        boxes.add(new AppBoxReference(0, subjectKey));

        return submitApplicationCall("UPDATE_STATUS", appArgs, boxes, didForLogs);
    }

    private String submitApplicationCall(
            String method,
            List<byte[]> appArgs,
            List<AppBoxReference> boxes,
            String didForLogs
    ) {
        int maxAttempts = 3;
        long delayMs = 1000;

        Exception lastException = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                TransactionParametersResponse params = algodClient.TransactionParams().execute().body();

                Transaction txn = Transaction.ApplicationCallTransactionBuilder()
                        .sender(algorandAdminAccount.getAddress())
                        .suggestedParams(params)
                        .applicationId(appId)
                        .args(appArgs)
                        .boxReferences(boxes)
                        .build();

                SignedTransaction signedTxn = algorandAdminAccount.signTransaction(txn);
                byte[] encodedTxBytes = Encoder.encodeToMsgPack(signedTxn);

                Response<PostTransactionsResponse> submitResponse = algodClient.RawTransaction()
                        .rawtxn(encodedTxBytes)
                        .execute();

                if (!submitResponse.isSuccessful()) {
                    throw new IllegalStateException("Echec de soumission de la transaction Algorand: " + submitResponse.message());
                }

                String txId = submitResponse.body().txId;
                PendingTransactionResponse confirmed = waitForConfirmation(txId, 4);

                log.info("Transaction Algorand {} confirmee pour DID={} - round={} - txId={} (tentative {}/{})",
                        method, didForLogs, confirmed.confirmedRound, txId, attempt, maxAttempts);

                return txId;

            } catch (Exception e) {
                lastException = e;
                log.warn("Echec tentative {}/{} de l'appel Algorand (method={}, did={}): {}",
                        attempt, maxAttempts, method, didForLogs, e.getMessage());

                if (attempt < maxAttempts) {
                    try {
                        Thread.sleep(delayMs);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    delayMs *= 2; // backoff exponentiel : 1s, 2s
                }
            }
        }

        log.error("Echec definitif de l'appel au smart contract Algorand apres {} tentatives (method={}, did={}): {}",
                maxAttempts, method, didForLogs, lastException != null ? lastException.getMessage() : "inconnu", lastException);
        auditLogService.record(
                EventType.ALGORAND_PUBLICATION_FAILED,
                didForLogs,
                ActorType.SYSTEM,
                false,
                "Echec publication on-chain apres " + maxAttempts + " tentatives (" + method + ") : "
                        + (lastException != null ? lastException.getMessage() : "inconnu")
        );
        throw new IllegalStateException("Echec de la publication on-chain apres " + maxAttempts + " tentatives: "
                + (lastException != null ? lastException.getMessage() : "inconnu"), lastException);
    }

    private Optional<byte[]> readRawBox(byte[] boxName) throws Exception {
        String encodedBoxName = "b64:" + Base64.getEncoder().encodeToString(boxName);
        Response<Box> response = algodClient.GetApplicationBoxByName(appId).name(encodedBoxName).execute();
        if (!response.isSuccessful()) {
            return Optional.empty();
        }
        return Optional.of(response.body().value);
    }

    private PendingTransactionResponse waitForConfirmation(String txId, int timeoutRounds) throws Exception {
        Response<NodeStatusResponse> statusResponse = algodClient.GetStatus().execute();
        if (!statusResponse.isSuccessful()) {
            throw new IllegalStateException("Impossible de recuperer le statut du noeud Algorand");
        }
        long startRound = statusResponse.body().lastRound + 1;
        long currentRound = startRound;

        while (currentRound < startRound + timeoutRounds) {
            Response<PendingTransactionResponse> pendingResponse =
                    algodClient.PendingTransactionInformation(txId).execute();
            if (pendingResponse.isSuccessful()) {
                PendingTransactionResponse pending = pendingResponse.body();
                if (pending.confirmedRound != null && pending.confirmedRound > 0) {
                    return pending;
                }
            }
            algodClient.WaitForBlock(currentRound).execute();
            currentRound++;
        }

        throw new IllegalStateException("Transaction " + txId + " non confirmee apres " + timeoutRounds + " rounds");
    }

    private static long readUint64(byte[] data, int offset) {
        long value = 0;
        for (int i = offset; i < offset + 8; i++) {
            value = (value << 8) | (data[i] & 0xFFL);
        }
        return value;
    }

    private static String statusToLifecycle(byte status) {
        if (status == DID_STATUS_READY) {
            return "ACTIVE";
        }
        if (status == DID_STATUS_DELETED) {
            return "REVOKED";
        }
        if (status == DID_STATUS_UPLOADING) {
            return "PENDING";
        }
        return "UNKNOWN";
    }
}
