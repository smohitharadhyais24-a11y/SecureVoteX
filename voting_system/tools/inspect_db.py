import sqlite3

def main():
    db='debug_test.db'
    conn=sqlite3.connect(db)
    rows=list(conn.execute('SELECT booth_id, booth_name FROM booths'))
    print('Booths:', rows)
    rows2=list(conn.execute('SELECT * FROM election_config'))
    print('Elections:', rows2)
    conn.close()

if __name__=='__main__':
    main()
