from cifsacl import getfacl
import ldap

# ldapsearch -x -LLL -H ldap://dc.xxxx.org -s sub -b 'dc=xxxx,dc=org' -wxxxxx -D "xxxxx@xxxxx.org" "objectSid=S-1-5-21-1981756720-1202999891-1092489882-53260"
try:
	gf = getfacl("/mnt/cs_cifs/cs_researcher/xxxx/mcheck_sec25.ptp")
	con = ldap.initialize('ldap://dc.xxxxx.org')
	dn = "xxxx@xxx.org"
	pw = "xxxxx"
	base = "dc=xxxxx,dc=org"
	retrieve_attributes=["cn"]
	scope = ldap.SCOPE_SUBTREE
	con.set_option(ldap.OPT_REFERRALS, 0)
	con.simple_bind_s(dn,pw)
	counter = 0
	for perm in gf:
		if counter==0:
			print "OWNER: "+perm
		elif counter==1:
			print "GROUP: "+perm
		else:
			permstring = str(perm)
			sid = permstring[0:permstring.find('::')]
			filter = "objectSid=" + sid 
			result_id = con.search_s( base, ldap.SCOPE_SUBTREE, filter, retrieve_attributes )
			print result_id[0][1]["cn"][0]
			type = permstring[permstring.find('::')+2:permstring.rfind('::')]
			mask = permstring[permstring.rfind('::')+2:len(permstring)]
			print sid+" "+type+" "+mask
		counter=counter+1	
except Exception,exc:
	print str("ERROR: "+str(exc))	

