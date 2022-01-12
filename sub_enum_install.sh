#!/bin/bash

echo " INSTALLING REQUIERED TOOLS FOR SUBDOMAIN ENUMERATION......."

echo "INSTALLING SUBFINDER TOOL"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
echo "INSTALLING ASSETFINDER TOOL"
go get -u github.com/tomnomnom/assetfinder
echo "INSTALLING AMASS TOOL"
go get -v github.com/OWASP/Amass/v3/...
echo "INSTALLING FINDOMAIN TOOL"
 wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux
mv findomain-linux findomain
chmod +x findomain
mv findomain /usr/bin/
echo "INSTALLING WAYBACKURLS TOOL"
go get github.com/tomnomnom/waybackurls
echo "INSTALLING GAU TOOL"
 go install github.com/lc/gau/v2/cmd/gau@latest
echo "INSTALLING ANEW TOOL"
go get -u github.com/tomnomnom/anew
echo "INSTALLING UNFURL TOOL"
go get -u github.com/tomnomnom/unfurl
echo "INSTALLING CROBAT TOOL"
go get github.com/cgboal/sonarsearch/cmd/crobat
echo "INSTALLING GITHUB-SUBDOMAINS TOOL"
go get -u github.com/gwen001/github-subdomains
echo "INSTALLING CTFR.PY TOOL"
git clone https://github.com/UnaPibaGeek/ctfr.git $tools/ctfr
pip3 install -r $tools/ctfr/requirements.txt
echo "INSTALLING PUREDNS TOOL"
GO111MODULE=on go get github.com/d3mondev/puredns/v2
echo "INSTALLING DNSX TOOL"
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
echo "INSTALLING CERO TOOL"
go get -u github.com/glebarez/cero
echo "INSTALLING HTTPX TOOL"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
echo "INSTALLING GOSPIDER TOOL"
GO111MODULE=on go get -u github.com/jaeles-project/gospider
echo "INSTALLING ANALYTICS RELATIONSHIP TOOL"
 git clone https://github.com/Josue87/AnalyticsRelationships.git
go build -ldflags "-s -w" AnalyticsRelationships/
mv AnalyticsRelationships/analyticsrelationships /usr/local/bin
echo "INSTALLING GOTATOR TOOL"
go get github.com/Josue87/gotator