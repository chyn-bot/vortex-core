-- Migration 013: full LHDN classification catalogue
--
-- Every e-invoice line must carry a classification code; only "022
-- Others" was seeded (the rest expected an API code-sync). Portal-mode
-- tenants need the list locally — seed the complete MyInvois
-- classification table (001–045). "Sync LHDN codes" still refreshes
-- descriptions from the API when credentials exist.

INSERT INTO acc_lhdn_code (code_type, code, description) VALUES
    ('classification', '001', 'Breastfeeding equipment'),
    ('classification', '002', 'Child care centres and kindergartens fees'),
    ('classification', '003', 'Computer, smartphone or tablet'),
    ('classification', '004', 'Consolidated e-Invoice'),
    ('classification', '005', 'Construction materials (Fourth Schedule, LPIPM Act 1994)'),
    ('classification', '006', 'Disbursement'),
    ('classification', '007', 'Donation'),
    ('classification', '008', 'e-Commerce - e-Invoice to buyer / purchaser'),
    ('classification', '009', 'e-Commerce - Self-billed e-Invoice to seller, logistics etc.'),
    ('classification', '010', 'Education fees'),
    ('classification', '011', 'Goods on consignment (Consignor)'),
    ('classification', '012', 'Goods on consignment (Consignee)'),
    ('classification', '013', 'Gym membership'),
    ('classification', '014', 'Insurance - Education and medical benefits'),
    ('classification', '015', 'Insurance - Takaful or life insurance'),
    ('classification', '016', 'Interest and financing expenses'),
    ('classification', '017', 'Internet subscription'),
    ('classification', '018', 'Land and building'),
    ('classification', '019', 'Medical examination / rehabilitation for learning disabilities'),
    ('classification', '020', 'Medical examination or vaccination expenses'),
    ('classification', '021', 'Medical expenses for serious diseases'),
    ('classification', '023', 'Petroleum operations (Petroleum (Income Tax) Act 1967)'),
    ('classification', '024', 'Private retirement scheme or deferred annuity scheme'),
    ('classification', '025', 'Motor vehicle'),
    ('classification', '026', 'Subscription of books / journals / magazines / publications'),
    ('classification', '027', 'Reimbursement'),
    ('classification', '028', 'Rental of motor vehicle'),
    ('classification', '029', 'EV charging facilities (installation, rental, sale or subscription)'),
    ('classification', '030', 'Repair and maintenance'),
    ('classification', '031', 'Research and development'),
    ('classification', '032', 'Foreign income'),
    ('classification', '033', 'Self-billed - Betting and gaming'),
    ('classification', '034', 'Self-billed - Importation of goods'),
    ('classification', '035', 'Self-billed - Importation of services'),
    ('classification', '036', 'Self-billed - Others'),
    ('classification', '037', 'Self-billed - Monetary payment to agents, dealers or distributors'),
    ('classification', '038', 'Sports equipment / facilities / competitions (Sports Development Act 1997)'),
    ('classification', '039', 'Supporting equipment for disabled person'),
    ('classification', '040', 'Voluntary contribution to approved provident fund'),
    ('classification', '041', 'Dental examination or treatment'),
    ('classification', '042', 'Fertility treatment'),
    ('classification', '043', 'Treatment and home care nursing, daycare and residential care centres'),
    ('classification', '044', 'Vouchers, gift cards, loyalty points etc.'),
    ('classification', '045', 'Self-billed - Non-monetary payment to agents, dealers or distributors')
ON CONFLICT (code_type, code) DO NOTHING;
