from database.seed_data import seed_demo_voters
from security.hashing import generate_payload
from server.vote_verifier import process_vote

# Use a local temporary DB file
DB = 'debug_test.db'
seed_demo_voters(db_path=DB)
pl = generate_payload('A1:B2:C3:D4', 'A', 'booth01')
print('Payload:', pl)
res = process_vote(pl, db_path=DB)
print('Result:', res)
