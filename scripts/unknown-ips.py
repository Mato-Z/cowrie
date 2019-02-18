import mysql.connector

print 'Loading IPs to update...'
ips = open('unknown-ips.txt', "r").readlines()

print 'Connecting...'
cnx = mysql.connector.connect(user='root', database='matovt',
password='100rootABCDEF')
cursor = cnx.cursor()

for line in ips:
  (ip, asn, rir, country, asname) = line.split(';')
  print(ip + '...')
  cursor.execute('INSERT INTO `asinfo` (`asn`, `rir`, `country`, `asname`, `updated`) VALUES (%s, %s, %s, %s, TRUE, NOW())', (asn, rir, country, asname))
  asnid = cursor.lastrowid
  cursor.execute('UPDATE `sessions` SET `asnid`=%s WHERE `ip`=%s AND `asnid`=1', (asnid, ip))
  print("  " + str(cursor.rowcount) + " rows changed")    


cursor.close()
cnx.commit()
cnx.close()
