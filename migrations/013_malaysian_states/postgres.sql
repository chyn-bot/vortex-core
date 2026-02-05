-- Malaysian states and federal territories (ISO 3166-2:MY)
INSERT INTO states (country_id, code, name)
SELECT c.id, s.code, s.name FROM countries c, (VALUES
    ('JHR', 'Johor'),
    ('KDH', 'Kedah'),
    ('KTN', 'Kelantan'),
    ('MLK', 'Melaka'),
    ('NSN', 'Negeri Sembilan'),
    ('PHG', 'Pahang'),
    ('PNG', 'Pulau Pinang'),
    ('PRK', 'Perak'),
    ('PLS', 'Perlis'),
    ('SGR', 'Selangor'),
    ('TRG', 'Terengganu'),
    ('SBH', 'Sabah'),
    ('SWK', 'Sarawak'),
    ('KUL', 'Wilayah Persekutuan Kuala Lumpur'),
    ('LBN', 'Wilayah Persekutuan Labuan'),
    ('PJY', 'Wilayah Persekutuan Putrajaya')
) AS s(code, name) WHERE c.code = 'MY'
ON CONFLICT (country_id, code) DO NOTHING;
