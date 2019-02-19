import mysql.connector

ip_file_name = 'unknown-ips.txt'
db_host = ''
user_name = ''
database_name = ''
db_password = ''

print('Loading IPs to update...')
ips = open(ip_file_name, "r").readlines()

print('Connecting...')
cnx = mysql.connector.connect(host=db_host, user=user_name, database=database_name,
password=db_password)
cursor = cnx.cursor()

for line in ips:
  if line == '':
    continue

  (ip, asn, rir, country, asname) = line.split(';')
  print(ip + '...')
  cursor.execute("SELECT `asnid` FROM `asinfo` WHERE `asn`=%s AND `rir`=%s AND `country`=%s AND `asname`=%s AND `updated`=TRUE ", (asn, rir, country, asname))
  r = cursor.fetchall()
  if cursor.rowcount > 0:
    asnid = int(r[0][0])
    print("Matching AS record exists with ID " + str(asnid))
  else:
    cursor.execute('INSERT INTO `asinfo` (`asn`, `rir`, `country`, `asname`, `updated`, `updatedTime`) VALUES (%s, %s, %s, %s, TRUE, NOW())', (asn, rir, country, asname))
    asnid = cursor.lastrowid
  
  cursor.execute('UPDATE `sessions` SET `asnid`=%s WHERE `ip`=%s AND `asnid`=1', (asnid, ip))
  print("  " + str(cursor.rowcount) + " rows changed")    


cursor.close()
cnx.commit()
cnx.close()
