package com.validator.service.validators;

import com.validator.model.BlackList;
import com.validator.model.Transaction;
import com.validator.model.User;
import com.validator.model.enums.FraudReason;
import com.validator.model.enums.TransactionStatus;
import com.validator.repository.BlackListRepositoryImpl;
import com.validator.repository.TransactionRepositoryImpl;
import com.validator.repository.UserRepositoryImpl;
import com.validator.service.UserService;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.BooleanUtils;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class TransactionValidator {

    private static final List<String> DANGEROUS_TERMS = List.of("golpe", "fraude", "fake", "urgente");

    private final TransactionRepositoryImpl transactionRepository;
    private final BlackListRepositoryImpl blackListRepository;
    private final UserService userService;


    public Transaction validate(Transaction transaction) {
        User receiver = userService.getOrCreateUser(transaction.getReceiver());
        transaction.setReceiver(receiver);

        User sender = userService.getOrCreateUser(transaction.getSender());
        transaction.setSender(sender);

        validateUserBlacklist(transaction);
        validateTransactionValue(transaction);

        List<Transaction> lastTransactions = transactionRepository.findReceiverLast15Transactions(receiver.getId());
        validateHighFrequency(transaction, lastTransactions);
        validateOutOfAverageValue(transaction, lastTransactions);

        if (TransactionStatus.FAILED.equals(transaction.getStatus())) {
            return transaction;
        }

        validateDangerousDescription(transaction);
        validateDangerousKeys(transaction);

        if (TransactionStatus.PENDING_REVIEW.equals(transaction.getStatus())) {
            return transaction;
        }


        transaction.setStatus(TransactionStatus.SUCCESS);

        return transaction;
    }


    private void validateUserBlacklist(Transaction transaction) {
        List<User> users = List.of(transaction.getSender(), transaction.getReceiver());

        if (users.stream().anyMatch(this::isBlacklisted)) {
            transaction.setStatus(TransactionStatus.FAILED);
            transaction.setFraudReason(FraudReason.USER_IN_BLACKLIST);
        }
    }

    public void validateTransactionValue(Transaction transaction) {
        double TRANSACTION_MAX_VALUE = 10000.0;
        double TRANSACTION_MIN_VALUE = 0.5;

        if (transaction.getValue() > TRANSACTION_MAX_VALUE || transaction.getValue() < TRANSACTION_MIN_VALUE) {
            transaction.setStatus(TransactionStatus.FAILED);
            transaction.setFraudReason(FraudReason.STRANGE_VALUE);
            addUserToBlackList(transaction.getReceiver());
        }
    }

    public void validateDangerousDescription(Transaction transaction) {
        String normalizedDescription = transaction.getDescription().toLowerCase(Locale.ROOT);
        List<String> foundTerms = DANGEROUS_TERMS.stream().filter(normalizedDescription::contains).toList();

        if (BooleanUtils.isFalse(foundTerms.isEmpty())) {
            transaction.setStatus(TransactionStatus.PENDING_REVIEW);
            transaction.setFraudReason(FraudReason.SUSPICIOUS_DESCRIPTION);
        }
    }

    public void validateDangerousKeys(Transaction transaction) {
        List<String> usersKeys = List.of(transaction.getSender().getPixKey(), transaction.getReceiver().getPixKey());
        List<String> normalizedKeys = usersKeys.stream().map(key -> key.toLowerCase(Locale.ROOT)).toList();

        List<String> foundDangerousTerms = DANGEROUS_TERMS.stream().filter(normalizedKeys::contains).toList();

        if (BooleanUtils.isFalse(foundDangerousTerms.isEmpty())) {
            transaction.setStatus(TransactionStatus.PENDING_REVIEW);
            transaction.setFraudReason(FraudReason.SUSPICIOUS_PIX_KEY);
        }
    }

    public void validateHighFrequency(Transaction transaction, List<Transaction> recentTransactions) {
        long frequencyInMinutes = 5;

        long foundTransactions = recentTransactions.stream()
                .filter(t -> t.getCreatedDate() != null && Duration.between(t.getCreatedDate(), LocalDateTime.now()).toMinutes() <= frequencyInMinutes)
                .count();

        if (foundTransactions >= 5) {
            transaction.setStatus(TransactionStatus.FAILED);
            transaction.setFraudReason(FraudReason.HIGH_FREQUENCY);
            addUserToBlackList(transaction.getReceiver());
        }
    }

    public void validateOutOfAverageValue(Transaction transaction, List<Transaction> lastTransactions) {
        if (lastTransactions == null || lastTransactions.isEmpty() || lastTransactions.size() < 5) {
            return;
        }

        double average = lastTransactions.stream()
                .mapToDouble(Transaction::getValue)
                .average()
                .orElse(0.0);

        double toleranceFactor = 4.0;
        double upperLimit = average * toleranceFactor;
        double lowerLimit = average / toleranceFactor;

        if (transaction.getValue() > upperLimit || transaction.getValue() < lowerLimit) {
            transaction.setStatus(TransactionStatus.FAILED);
            transaction.setFraudReason(FraudReason.OUT_OF_AVERAGE_VALUE);
        }
    }

    public boolean isBlacklisted(User user) {
        return Objects.isNull(user.getId()) || blackListRepository.getUser(user.getId()).isPresent();
    }

    public void addUserToBlackList(User user) {
        blackListRepository.save(new BlackList(null, user, LocalDateTime.now()));
    }

}
