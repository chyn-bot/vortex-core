-- Down migration: AR/AP document layer
DROP TRIGGER IF EXISTS trg_acc_invoice_line_guard ON acc_invoice_line;
DROP FUNCTION IF EXISTS acc_invoice_line_guard();
DROP TABLE IF EXISTS acc_partial_reconcile;
DROP TABLE IF EXISTS acc_invoice_line;
