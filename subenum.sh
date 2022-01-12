#!/usr/bin/env bash

function subdomains_full(){
	NUMOFLINES_subs="0"
	NUMOFLINES_probed="0"
	printf "${bgreen}#######################################################################\n\n"
	! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && printf "${bblue} Subdomain Enumeration $domain\n\n"
	[[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && printf "${bblue} Scanning IP $domain\n\n"
	[ -s "subdomains/subdomains.txt" ] && cp subdomains/subdomains.txt .tmp/subdomains_old.txt
	[ -s "webs/webs.txt" ] && cp webs/webs.txt .tmp/probed_old.txt

	if ( [ ! -f "$called_fn_dir/.sub_active" ] || [ ! -f "$called_fn_dir/.sub_brute" ] || [ ! -f "$called_fn_dir/.sub_permut" ] || [ ! -f "$called_fn_dir/.sub_recursive" ] )  || [ "$DIFF" = true ] ; then
		resolvers_update
	fi

	[ -s "${inScope_file}" ] && cat ${inScope_file} | anew -q subdomains/subdomains.txt

	if ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && [ "$SUBDOMAINS_GENERAL" = true ]; then
		sub_passive
		sub_crt
		sub_active
		sub_brute
		sub_permut
		sub_recursive
		sub_dns
		sub_scraping
		sub_analytics
	else 
		notification "IP/CIDR detected, subdomains search skipped" info
		echo $domain | anew -q subdomains/subdomains.txt
	fi
}
#### PASSIVE ENUMERATION ##
function sub_passive() {
echo "Running : Passive Subdomain Enumeration"

subfinder -d $domain -all -o .tmp/subfinder_psub.txt  &>/dev/null
			assetfinder --subs-only $domain  | anew -q .tmp/assetfinder_psub.txt
			amass enum -passive -d $domain -config $AMASS_CONFIG -o .tmp/amass_psub.txt  &>/dev/null
			findomain --quiet -t $domain -u .tmp/findomain_psub.txt  &>/dev/null
			timeout 10m waybackurls $domain | unfurl -u domains  | anew -q .tmp/waybackurls_psub.txt
			timeout 10m gau --subs --threads $GAUPLUS_THREADS $domain | unfurl -u domains  | anew -q .tmp/gau_psub.txt


#####

crobat -s $domain  | anew -q .tmp/crobat_psub.txt
		
github-subdomains -d $domain -t $GITHUB_TOKENS -o .tmp/github_subdomains_psub.txt  &>/dev/null

#### api scan

	curl -s -k "https://jldc.me/anubis/subdomains/${domain}"  | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sed '/^\./d' | anew -q .tmp/curl_psub.txt
		curl -s -k "https://dns.bufferover.run/dns?q=.${domain}"  | jq -r '.FDNS_A'[],'.RDNS'[]  | cut -d ',' -f2 | grep -F ".$domain" | anew -q .tmp/curl_psub.txt
		curl -s -k "https://tls.bufferover.run/dns?q=.${domain}"  | jq -r .Results[]  | cut -d ',' -f4 | grep -F ".$domain" | anew -q .tmp/curl_psub.txt
		NUMOFLINES=$(cat .tmp/*_psub.txt  | sed "s/*.//" | anew .tmp/passive_subs.txt | wc -l)
		echo "${NUMOFLINES} new subs (passive)" 

}
##### apis done & passive done ##
function sub_crt() {
echo "Running : Crtsh Subdomain Enumeration"
			python3 $tools/ctfr/ctfr.py -d $domain -o .tmp/crtsh_subs_tmp.txt  &>/dev/null

eval sed -i '1,11d' .tmp/crtsh_subs_tmp.txt  &>/dev/null
		NUMOFLINES=$(cat .tmp/crtsh_subs_tmp.txt  | anew .tmp/crtsh_subs.txt | wc -l)
	echo "${NUMOFLINES} new subs (cert transparency)" 
}
#### crt done ####
function sub_active() {
echo  "Running : Active Subdomain Enumeration"
		cat .tmp/*_subs.txt  | anew -q .tmp/subs_no_resolved.txt
		
puredns resolve .tmp/subs_no_resolved.txt -w .tmp/subdomains_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT &>/dev/null


echo $domain | dnsx -retry 3 -silent -r $resolvers_trusted  | anew -q .tmp/subdomains_tmp.txt


cat .tmp/subdomains_tmp.txt | cero -p $TLS_PORTS  | sed 's/^*.//' | grep -aE "\." | anew -q .tmp/subdomains_tmp.txt


NUMOFLINES=$(cat .tmp/subdomains_tmp.txt  | grep "\.$domain$\|^$domain$" | anew subdomains/subdomains.txt | wc -l)
		echo "${NUMOFLINES} new subs (active resolution)" 

}
### DNA SCAN
function sub_dns() {
		echo  "Running : DNS Subdomain Enumeration"

 dnsx -retry 3 -a -aaaa -cname -ns -ptr -mx -soa -resp -silent -l subdomains/subdomains.txt -o subdomains/subdomains_dnsregs.txt -r $resolvers_trusted  &>/dev/null && cat subdomains/subdomains_dnsregs.txt | cut -d '[' -f2 | sed 's/.$//' | grep ".$domain$" | anew -q .tmp/subdomains_dns.txt  && puredns resolve .tmp/subdomains_dns.txt -w .tmp/subdomains_dns_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT  &>/dev/null

		NUMOFLINES=$(cat .tmp/subdomains_dns_resolved.txt  | grep "\.$domain$\|^$domain$" | anew subdomains/subdomains.txt | wc -l)
		echo "${NUMOFLINES} new subs (dns resolution)" 
}
## DNS SCAN COMPLETED ##
function sub_brute() {

		echo  "Running : Bruteforce Subdomain Enumeration"

puredns bruteforce $subs_wordlist_big $domain -w .tmp/subs_brute.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT  &>/dev/null  && puredns resolve .tmp/subs_brute.txt -w .tmp/subs_brute_valid.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT  &>/dev/null
	
	
		NUMOFLINES=$(cat .tmp/subs_brute_valid.txt  | sed "s/*.//" | grep ".$domain$" | anew subdomains/subdomains.txt | wc -l)
		
		echo "${NUMOFLINES} new subs (bruteforce)" 
}
### BRUTE FORCE COMPLETE
function sub_scraping() {
echo "Running : Source code scraping subdomain search"
		touch .tmp/scrap_subs.txt
		
				cat subdomains/subdomains.txt | httpx -follow-host-redirects -H "${HEADER}" -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | grep ".$domain$" | anew -q .tmp/probed_tmp_scrap.txt   && cat .tmp/probed_tmp_scrap.txt | httpx -tls-grab -tls-probe -csp-probe -H "${HEADER}" -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | grep ".$domain$" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains  | anew -q .tmp/scrap_subs.txt   && gospider -S .tmp/probed_tmp_scrap.txt --js -t $GOSPIDER_THREADS -d 3 --sitemap --robots -w -r > .tmp/gospider.txt


				sed -i '/^.\{2048\}./d' .tmp/gospider.txt && cat .tmp/gospider.txt | grep -aEo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains  | grep ".$domain$" | anew -q .tmp/scrap_subs.txt  && puredns resolve .tmp/scrap_subs.txt -w .tmp/scrap_subs_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT  &>/dev/null
				NUMOFLINES=$(cat .tmp/scrap_subs_resolved.txt  | grep "\.$domain$\|^$domain$" | anew subdomains/subdomains.txt | tee .tmp/diff_scrap.txt | wc -l) && cat .tmp/diff_scrap.txt | httpx -follow-host-redirects -H "${HEADER}" -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | grep ".$domain$" | anew -q .tmp/probed_tmp_scrap.txt

echo "${NUMOFLINES} new subs (code scraping)" 

}
### SCRAPING COMPLETE
function sub_analytics() {
echo "Running : Analytics Subdomain Enumeration"


			mkdir -p .tmp/output_analytics/
			cat .tmp/probed_tmp_scrap.txt | analyticsrelationships >> .tmp/analytics_subs_tmp.txt  &>/dev/null

 cat .tmp/analytics_subs_tmp.txt | grep "\.$domain$\|^$domain$" | sed "s/|__ //" | anew -q .tmp/analytics_subs_clean.txt
		
 puredns resolve .tmp/analytics_subs_clean.txt -w .tmp/analytics_subs_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT  &>/dev/null


		NUMOFLINES=$(cat .tmp/analytics_subs_resolved.txt  | anew subdomains/subdomains.txt |  wc -l)
		echo "${NUMOFLINES} new subs (analytics relationship)" 
}
### ANALYTICS COMPLETE##
function sub_permut() {
  
echo  "Running : Permutations Subdomain Enumeration"
		if [ "$DEEP" = true ] || [ "$(cat subdomains/subdomains.txt | wc -l)" -le $DEEP_LIMIT ] ; then
			[ -s "subdomains/subdomains.txt" ] && gotator -sub subdomains/subdomains.txt -perm $tools/permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md -silent  > .tmp/gotator1.txt
		elif [ "$(cat .tmp/subs_no_resolved.txt | wc -l)" -le $DEEP_LIMIT2 ]; then
			[ -s ".tmp/subs_no_resolved.txt" ] && gotator -sub .tmp/subs_no_resolved.txt -perm $tools/permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md -silent  > .tmp/gotator1.txt
		else
			echo "Skipping Permutations: Too Many Subdomains" 
			return 1
		fi

 puredns resolve .tmp/gotator1.txt -w .tmp/permute1_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT  &>/dev/null

cat .tmp/permute1_tmp.txt | anew -q .tmp/permute1.txt

gotator -sub .tmp/permute1.txt -perm $tools/permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md -silent  > .tmp/gotator2.txt
	
	
	 puredns resolve .tmp/gotator2.txt -w .tmp/permute2_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT  &>/dev/null


cat .tmp/permute2_tmp.txt | anew -q .tmp/permute2.txt

cat .tmp/permute1.txt .tmp/permute2.txt  | anew -q .tmp/permute_subs.txt


			NUMOFLINES=$(cat .tmp/permute_subs.txt  | grep ".$domain$" | anew subdomains/subdomains.txt | wc -l)

echo "${NUMOFLINES} new subs (permutations)" 

}
######## PERMUTATIONS COMPLETE #####
function sub_recursive(){
	if { [ ! -f "$called_fn_dir/." ] || [ "$DIFF" = true ]; } && [ "$SUBRECURSIVE" = true ] && [ -s "subdomains/subdomains.txt" ]; then
		start_subfunc  "Running : Subdomains recursive search"


###### Passive recursive ##

for sub in $( ( cat subdomains/subdomains.txt | rev | cut -d '.' -f 3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 && cat subdomains/subdomains.txt | rev | cut -d '.' -f 4,3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 ) | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f 2);do 
					subfinder -d $sub -all -silent  | anew -q .tmp/passive_recursive.txt
					assetfinder --subs-only $sub  | anew -q .tmp/passive_recursive.txt
					amass enum -passive -d $sub -config $AMASS_CONFIG  | anew -q .tmp/passive_recursive.txt
					findomain --quiet -t $sub  | anew -q .tmp/passive_recursive.txt
				done
				[ -s ".tmp/passive_recursive.txt" ] && puredns resolve .tmp/passive_recursive.txt -w .tmp/passive_recurs_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT  &>/dev/null


		# Bruteforce recursive

		if [[ $(cat subdomains/subdomains.txt | wc -l) -le $DEEP_LIMIT ]] && [ "$SUB_RECURSIVE_BRUTE" = true ] ; then
			echo "" > .tmp/brute_recursive_wordlist.txt
			for sub in $(cat subdomains/subdomains.txt); do
				sed "s/$/.$sub/" $subs_wordlist >> .tmp/brute_recursive_wordlist.txt
			done


			[ -s ".tmp/brute_recursive_wordlist.txt" ] && puredns resolve .tmp/brute_recursive_wordlist.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -w .tmp/brute_recursive_result.txt  &>/dev/null




			[ -s ".tmp/brute_recursive_result.txt" ] && cat .tmp/brute_recursive_result.txt | anew -q .tmp/brute_recursive.txt
			[ -s ".tmp/brute_recursive.txt" ] && gotator -sub .tmp/brute_recursive.txt -perm $tools/permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md -silent  > .tmp/gotator1_recursive.txt



			[ -s ".tmp/gotator1_recursive.txt" ] && puredns resolve .tmp/gotator1_recursive.txt -w .tmp/permute1_recursive_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT  &>/dev/null



			[ -s ".tmp/permute1_recursive_tmp.txt" ] && cat .tmp/permute1_recursive_tmp.txt  | anew -q .tmp/permute1_recursive.txt
			[ -s ".tmp/permute1_recursive.txt" ] && gotator -sub .tmp/permute1_recursive.txt -perm $tools/permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md -silent  > .tmp/gotator2_recursive.txt


			[ -s ".tmp/gotator2_recursive.txt" ] && puredns resolve .tmp/gotator2_recursive.txt -w .tmp/permute2_recursive_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT  &>/dev/null
		
			cat .tmp/permute1_recursive.txt .tmp/permute2_recursive_tmp.txt  | anew -q .tmp/permute_recursive.txt
			
			
		NUMOFLINES=$(cat .tmp/passive_recurs_tmp.txt .tmp/permute_recursive.txt .tmp/brute_recursive.txt  | grep "\.$domain$\|^$domain$" | anew subdomains/subdomains.txt | wc -l)
		echo "${NUMOFLINES} new subs (recursive)" 
}
## RECURSIVE COMPLETE