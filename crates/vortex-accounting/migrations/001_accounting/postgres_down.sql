-- Down migration: Accounting base
DROP TRIGGER IF EXISTS trg_acc_move_line_guard ON acc_move_line;
DROP TRIGGER IF EXISTS trg_acc_move_guard ON acc_move;
DROP FUNCTION IF EXISTS acc_move_line_guard();
DROP FUNCTION IF EXISTS acc_move_guard();
DROP TABLE IF EXISTS acc_config;
DROP TABLE IF EXISTS acc_move_line;
DROP TABLE IF EXISTS acc_move;
DROP TABLE IF EXISTS acc_journal;
DROP TABLE IF EXISTS acc_account;
