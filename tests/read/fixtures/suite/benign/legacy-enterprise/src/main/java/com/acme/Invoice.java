package com.acme;

import java.math.BigDecimal;
import java.time.LocalDate;

public record Invoice(String customer, BigDecimal amount, LocalDate due) {
    public boolean overdue(LocalDate on) {
        return on.isAfter(due);
    }
}
