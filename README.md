# thesis-custom-soar
This custom SOAR solution written in Python (Flask) and Bash is used to receive webhook alerts from Splunk Enterprise and orchestrate active defense measures. It automates threat containment on Linux endpoints by dynamically blocking IPs (UFW) and terminating malicious connections (conntrack). It also automates the creation of cases in IRIS.
