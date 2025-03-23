

"
Common Weakness Enumeration
A community-developed list of SW & HW weaknesses that can become vulnerabilities


Home > CWE List > CWE-1333: Inefficient Regular Expression Complexity (4.16)  	
ID Lookup:  
Home About ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼ Search
CWE-1333: Inefficient Regular Expression Complexity
Weakness ID: 1333
Vulnerability Mapping: ALLOWED
Abstraction: Base
View customized information:
Conceptual
Operational
Mapping Friendly
Complete
Custom
 Description
The product uses a regular expression with an inefficient, possibly exponential worst-case computational complexity that consumes excessive CPU cycles.
 Extended Description
 Alternate Terms
ReDoS:	
ReDoS is an abbreviation of "Regular expression Denial of Service".
Regular Expression Denial of Service:	
While this term is attack-focused, this is commonly used to describe the weakness.
Catastrophic backtracking:	
This term is used to describe the behavior of the regular expression as a negative technical impact.
 Common Consequences
 Potential Mitigations
 Relationships
 Modes Of Introduction

Phase	Note
Implementation	A RegEx can be easy to create and read using unbounded matching characters, but the programmer might not consider the risk of excessive backtracking.
 Applicable Platforms
 Likelihood Of Exploit
High
 Demonstrative Examples
Example 1

This example attempts to check if an input string is a "sentence" [REF-1164].

(bad code)
Example Language: JavaScript 
var test_string = "Bad characters: $@#";
var bad_pattern = /^(\w+\s?)*$/i;
var result = test_string.search(bad_pattern);
The regular expression has a vulnerable backtracking clause inside (\w+\s?)*$ which can be triggered to cause a Denial of Service by processing particular phrases.

To fix the backtracking problem, backtracking is removed with the ?= portion of the expression which changes it to a lookahead and the \2 which prevents the backtracking. The modified example is:

(good code)
Example Language: JavaScript 
var test_string = "Bad characters: $@#";
var good_pattern = /^((?=(\w+))\2\s?)*$/i;
var result = test_string.search(good_pattern);
Note that [REF-1164] has a more thorough (and lengthy) explanation of everything going on within the RegEx.


Example 2

This example attempts to check if an input string is a "sentence" and is modified for Perl [REF-1164].

(bad code)
Example Language: Perl 
my $test_string = "Bad characters: \$\@\#";
my $bdrslt = $test_string;
$bdrslt =~ /^(\w+\s?)*$/i;
The regular expression has a vulnerable backtracking clause inside (\w+\s?)*$ which can be triggered to cause a Denial of Service by processing particular phrases.

To fix the backtracking problem, backtracking is removed with the ?= portion of the expression which changes it to a lookahead and the \2 which prevents the backtracking. The modified example is:

(good code)
Example Language: Perl 
my $test_string = "Bad characters: \$\@\#";
my $gdrslt = $test_string;
$gdrslt =~ /^((?=(\w+))\2\s?)*$/i;
Note that [REF-1164] has a more thorough (and lengthy) explanation of everything going on within the RegEx.


 Observed Examples
Reference	Description
CVE-2020-5243
server allows ReDOS with crafted User-Agent strings, due to overlapping capture groups that cause excessive backtracking.
CVE-2021-21317
npm package for user-agent parser prone to ReDoS due to overlapping capture groups
CVE-2019-16215
Markdown parser uses inefficient regex when processing a message, allowing users to cause CPU consumption and delay preventing processing of other messages.
CVE-2019-6785
Long string in a version control product allows DoS due to an inefficient regex.
CVE-2019-12041
Javascript code allows ReDoS via a long string due to excessive backtracking.
CVE-2015-8315
ReDoS when parsing time.
CVE-2015-8854
ReDoS when parsing documents.
CVE-2017-16021
ReDoS when validating URL.
 Memberships

Nature	Type	ID	Name
MemberOf		1416	Comprehensive Categorization: Resource Lifecycle Management
 Vulnerability Mapping Notes
Usage: ALLOWED (this CWE ID may be used to map to real-world vulnerabilities)
Reason: Acceptable-Use

Rationale:

This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities.
Comments:

Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.
 Related Attack Patterns
CAPEC-ID	Attack Pattern Name
CAPEC-492	Regular Expression Exponential Blowup
 References
[REF-1180] Scott A. Crosby. "Regular Expression Denial of Service". 2003-08. <https://web.archive.org/web/20031120114522/http://www.cs.rice.edu/~scrosby/hash/slides/USENIX-RegexpWIP.2.ppt>.
[REF-1162] Jan Goyvaerts. "Runaway Regular Expressions: Catastrophic Backtracking". 2019-12-22. <https://www.regular-expressions.info/catastrophic.html>.
[REF-1163] Adar Weidman. "Regular expression Denial of Service - ReDoS". <https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS>.
[REF-1164] Ilya Kantor. "Catastrophic backtracking". 2020-12-13. <https://javascript.info/regexp-catastrophic-backtracking>.
[REF-1165] Cristian-Alexandru Staicu and Michael Pradel. "Freezing the Web: A Study of ReDoS Vulnerabilities in JavaScript-based Web Servers". USENIX Security Symposium. 2018-07-11. <https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-staicu.pdf>.
[REF-1166] James C. Davis, Christy A. Coghlan, Francisco Servant and Dongyoon Lee. "The Impact of Regular Expression Denial of Service (ReDoS) in Practice: An Empirical Study at the Ecosystem Scale". 2018-08-01. <https://fservant.github.io/papers/Davis_Coghlan_Servant_Lee_ESECFSE18.pdf>. URL validated: 2023-04-07.
[REF-1167] James Davis. "The Regular Expression Denial of Service (ReDoS) cheat-sheet". 2020-05-23. <https://levelup.gitconnected.com/the-regular-expression-denial-of-service-redos-cheat-sheet-a78d0ed7d865>.
 Content History
 Submissions
Submission Date	Submitter	Organization
2021-01-17
(CWE 4.4, 2021-03-15)	Anonymous External Contributor	
 Modifications
Page Last Updated: November 19, 2024
 

Site Map
|
Terms of Use
|
Manage Cookies
|
Cookie Notice
|
Privacy Policy
|
Contact Us
|






Use of the Common Weakness Enumeration (CWE™) and the associated references from this website are subject to the Terms of Use. CWE is sponsored by the U.S. Department of Homeland Security (DHS) Cybersecurity and Infrastructure Security Agency (CISA) and managed by the Homeland Security Systems Engineering and Development Institute (HSSEDI) which is operated by The MITRE Corporation (MITRE). Copyright © 2006–2025, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation.

"
"
Common Weakness Enumeration
A community-developed list of SW & HW weaknesses that can become vulnerabilities


Home > CWE List > CWE-1333: Inefficient Regular Expression Complexity (4.16)  	
ID Lookup:  
Home About ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼ Search
CWE-1333: Inefficient Regular Expression Complexity
Weakness ID: 1333
Vulnerability Mapping: ALLOWED
Abstraction: Base
View customized information:
Conceptual
Operational
Mapping Friendly
Complete
Custom
 Description
The product uses a regular expression with an inefficient, possibly exponential worst-case computational complexity that consumes excessive CPU cycles.
 Extended Description
 Alternate Terms
ReDoS:	
ReDoS is an abbreviation of "Regular expression Denial of Service".
Regular Expression Denial of Service:	
While this term is attack-focused, this is commonly used to describe the weakness.
Catastrophic backtracking:	
This term is used to describe the behavior of the regular expression as a negative technical impact.
 Common Consequences
 Potential Mitigations
 Relationships
 Modes Of Introduction

Phase	Note
Implementation	A RegEx can be easy to create and read using unbounded matching characters, but the programmer might not consider the risk of excessive backtracking.
 Applicable Platforms
 Likelihood Of Exploit
High
 Demonstrative Examples
Example 1

This example attempts to check if an input string is a "sentence" [REF-1164].

(bad code)
Example Language: JavaScript 
var test_string = "Bad characters: $@#";
var bad_pattern = /^(\w+\s?)*$/i;
var result = test_string.search(bad_pattern);
The regular expression has a vulnerable backtracking clause inside (\w+\s?)*$ which can be triggered to cause a Denial of Service by processing particular phrases.

To fix the backtracking problem, backtracking is removed with the ?= portion of the expression which changes it to a lookahead and the \2 which prevents the backtracking. The modified example is:

(good code)
Example Language: JavaScript 
var test_string = "Bad characters: $@#";
var good_pattern = /^((?=(\w+))\2\s?)*$/i;
var result = test_string.search(good_pattern);
Note that [REF-1164] has a more thorough (and lengthy) explanation of everything going on within the RegEx.


Example 2

This example attempts to check if an input string is a "sentence" and is modified for Perl [REF-1164].

(bad code)
Example Language: Perl 
my $test_string = "Bad characters: \$\@\#";
my $bdrslt = $test_string;
$bdrslt =~ /^(\w+\s?)*$/i;
The regular expression has a vulnerable backtracking clause inside (\w+\s?)*$ which can be triggered to cause a Denial of Service by processing particular phrases.

To fix the backtracking problem, backtracking is removed with the ?= portion of the expression which changes it to a lookahead and the \2 which prevents the backtracking. The modified example is:

(good code)
Example Language: Perl 
my $test_string = "Bad characters: \$\@\#";
my $gdrslt = $test_string;
$gdrslt =~ /^((?=(\w+))\2\s?)*$/i;
Note that [REF-1164] has a more thorough (and lengthy) explanation of everything going on within the RegEx.


 Observed Examples
Reference	Description
CVE-2020-5243
server allows ReDOS with crafted User-Agent strings, due to overlapping capture groups that cause excessive backtracking.
CVE-2021-21317
npm package for user-agent parser prone to ReDoS due to overlapping capture groups
CVE-2019-16215
Markdown parser uses inefficient regex when processing a message, allowing users to cause CPU consumption and delay preventing processing of other messages.
CVE-2019-6785
Long string in a version control product allows DoS due to an inefficient regex.
CVE-2019-12041
Javascript code allows ReDoS via a long string due to excessive backtracking.
CVE-2015-8315
ReDoS when parsing time.
CVE-2015-8854
ReDoS when parsing documents.
CVE-2017-16021
ReDoS when validating URL.
 Memberships

Nature	Type	ID	Name
MemberOf		1416	Comprehensive Categorization: Resource Lifecycle Management
 Vulnerability Mapping Notes
Usage: ALLOWED (this CWE ID may be used to map to real-world vulnerabilities)
Reason: Acceptable-Use

Rationale:

This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities.
Comments:

Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.
 Related Attack Patterns
CAPEC-ID	Attack Pattern Name
CAPEC-492	Regular Expression Exponential Blowup
 References
[REF-1180] Scott A. Crosby. "Regular Expression Denial of Service". 2003-08. <https://web.archive.org/web/20031120114522/http://www.cs.rice.edu/~scrosby/hash/slides/USENIX-RegexpWIP.2.ppt>.
[REF-1162] Jan Goyvaerts. "Runaway Regular Expressions: Catastrophic Backtracking". 2019-12-22. <https://www.regular-expressions.info/catastrophic.html>.
[REF-1163] Adar Weidman. "Regular expression Denial of Service - ReDoS". <https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS>.
[REF-1164] Ilya Kantor. "Catastrophic backtracking". 2020-12-13. <https://javascript.info/regexp-catastrophic-backtracking>.
[REF-1165] Cristian-Alexandru Staicu and Michael Pradel. "Freezing the Web: A Study of ReDoS Vulnerabilities in JavaScript-based Web Servers". USENIX Security Symposium. 2018-07-11. <https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-staicu.pdf>.
[REF-1166] James C. Davis, Christy A. Coghlan, Francisco Servant and Dongyoon Lee. "The Impact of Regular Expression Denial of Service (ReDoS) in Practice: An Empirical Study at the Ecosystem Scale". 2018-08-01. <https://fservant.github.io/papers/Davis_Coghlan_Servant_Lee_ESECFSE18.pdf>. URL validated: 2023-04-07.
[REF-1167] James Davis. "The Regular Expression Denial of Service (ReDoS) cheat-sheet". 2020-05-23. <https://levelup.gitconnected.com/the-regular-expression-denial-of-service-redos-cheat-sheet-a78d0ed7d865>.
 Content History
 Submissions
Submission Date	Submitter	Organization
2021-01-17
(CWE 4.4, 2021-03-15)	Anonymous External Contributor	
 Modifications
Page Last Updated: November 19, 2024
 

Site Map
|
Terms of Use
|
Manage Cookies
|
Cookie Notice
|
Privacy Policy
|
Contact Us
|






Use of the Common Weakness Enumeration (CWE™) and the associated references from this website are subject to the Terms of Use. CWE is sponsored by the U.S. Department of Homeland Security (DHS) Cybersecurity and Infrastructure Security Agency (CISA) and managed by the Homeland Security Systems Engineering and Development Institute (HSSEDI) which is operated by The MITRE Corporation (MITRE). Copyright © 2006–2025, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation.

"
"
Common Weakness Enumeration
A community-developed list of SW & HW weaknesses that can become vulnerabilities


Home > CWE List > CWE-1333: Inefficient Regular Expression Complexity (4.16)  	
ID Lookup:  
Home About ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼ Search
CWE-1333: Inefficient Regular Expression Complexity
Weakness ID: 1333
Vulnerability Mapping: ALLOWED
Abstraction: Base
View customized information:
Conceptual
Operational
Mapping Friendly
Complete
Custom
 Description
The product uses a regular expression with an inefficient, possibly exponential worst-case computational complexity that consumes excessive CPU cycles.
 Extended Description
 Alternate Terms
ReDoS:	
ReDoS is an abbreviation of "Regular expression Denial of Service".
Regular Expression Denial of Service:	
While this term is attack-focused, this is commonly used to describe the weakness.
Catastrophic backtracking:	
This term is used to describe the behavior of the regular expression as a negative technical impact.
 Common Consequences
 Potential Mitigations
 Relationships
 Modes Of Introduction

Phase	Note
Implementation	A RegEx can be easy to create and read using unbounded matching characters, but the programmer might not consider the risk of excessive backtracking.
 Applicable Platforms
 Likelihood Of Exploit
High
 Demonstrative Examples
Example 1

This example attempts to check if an input string is a "sentence" [REF-1164].

(bad code)
Example Language: JavaScript 
var test_string = "Bad characters: $@#";
var bad_pattern = /^(\w+\s?)*$/i;
var result = test_string.search(bad_pattern);
The regular expression has a vulnerable backtracking clause inside (\w+\s?)*$ which can be triggered to cause a Denial of Service by processing particular phrases.

To fix the backtracking problem, backtracking is removed with the ?= portion of the expression which changes it to a lookahead and the \2 which prevents the backtracking. The modified example is:

(good code)
Example Language: JavaScript 
var test_string = "Bad characters: $@#";
var good_pattern = /^((?=(\w+))\2\s?)*$/i;
var result = test_string.search(good_pattern);
Note that [REF-1164] has a more thorough (and lengthy) explanation of everything going on within the RegEx.


Example 2

This example attempts to check if an input string is a "sentence" and is modified for Perl [REF-1164].

(bad code)
Example Language: Perl 
my $test_string = "Bad characters: \$\@\#";
my $bdrslt = $test_string;
$bdrslt =~ /^(\w+\s?)*$/i;
The regular expression has a vulnerable backtracking clause inside (\w+\s?)*$ which can be triggered to cause a Denial of Service by processing particular phrases.

To fix the backtracking problem, backtracking is removed with the ?= portion of the expression which changes it to a lookahead and the \2 which prevents the backtracking. The modified example is:

(good code)
Example Language: Perl 
my $test_string = "Bad characters: \$\@\#";
my $gdrslt = $test_string;
$gdrslt =~ /^((?=(\w+))\2\s?)*$/i;
Note that [REF-1164] has a more thorough (and lengthy) explanation of everything going on within the RegEx.


 Observed Examples
Reference	Description
CVE-2020-5243
server allows ReDOS with crafted User-Agent strings, due to overlapping capture groups that cause excessive backtracking.
CVE-2021-21317
npm package for user-agent parser prone to ReDoS due to overlapping capture groups
CVE-2019-16215
Markdown parser uses inefficient regex when processing a message, allowing users to cause CPU consumption and delay preventing processing of other messages.
CVE-2019-6785
Long string in a version control product allows DoS due to an inefficient regex.
CVE-2019-12041
Javascript code allows ReDoS via a long string due to excessive backtracking.
CVE-2015-8315
ReDoS when parsing time.
CVE-2015-8854
ReDoS when parsing documents.
CVE-2017-16021
ReDoS when validating URL.
 Memberships

Nature	Type	ID	Name
MemberOf		1416	Comprehensive Categorization: Resource Lifecycle Management
 Vulnerability Mapping Notes
Usage: ALLOWED (this CWE ID may be used to map to real-world vulnerabilities)
Reason: Acceptable-Use

Rationale:

This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities.
Comments:

Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.
 Related Attack Patterns
CAPEC-ID	Attack Pattern Name
CAPEC-492	Regular Expression Exponential Blowup
 References
[REF-1180] Scott A. Crosby. "Regular Expression Denial of Service". 2003-08. <https://web.archive.org/web/20031120114522/http://www.cs.rice.edu/~scrosby/hash/slides/USENIX-RegexpWIP.2.ppt>.
[REF-1162] Jan Goyvaerts. "Runaway Regular Expressions: Catastrophic Backtracking". 2019-12-22. <https://www.regular-expressions.info/catastrophic.html>.
[REF-1163] Adar Weidman. "Regular expression Denial of Service - ReDoS". <https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS>.
[REF-1164] Ilya Kantor. "Catastrophic backtracking". 2020-12-13. <https://javascript.info/regexp-catastrophic-backtracking>.
[REF-1165] Cristian-Alexandru Staicu and Michael Pradel. "Freezing the Web: A Study of ReDoS Vulnerabilities in JavaScript-based Web Servers". USENIX Security Symposium. 2018-07-11. <https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-staicu.pdf>.
[REF-1166] James C. Davis, Christy A. Coghlan, Francisco Servant and Dongyoon Lee. "The Impact of Regular Expression Denial of Service (ReDoS) in Practice: An Empirical Study at the Ecosystem Scale". 2018-08-01. <https://fservant.github.io/papers/Davis_Coghlan_Servant_Lee_ESECFSE18.pdf>. URL validated: 2023-04-07.
[REF-1167] James Davis. "The Regular Expression Denial of Service (ReDoS) cheat-sheet". 2020-05-23. <https://levelup.gitconnected.com/the-regular-expression-denial-of-service-redos-cheat-sheet-a78d0ed7d865>.
 Content History
 Submissions
Submission Date	Submitter	Organization
2021-01-17
(CWE 4.4, 2021-03-15)	Anonymous External Contributor	
 Modifications
Page Last Updated: November 19, 2024
 

Site Map
|
Terms of Use
|
Manage Cookies
|
Cookie Notice
|
Privacy Policy
|
Contact Us
|






Use of the Common Weakness Enumeration (CWE™) and the associated references from this website are subject to the Terms of Use. CWE is sponsored by the U.S. Department of Homeland Security (DHS) Cybersecurity and Infrastructure Security Agency (CISA) and managed by the Homeland Security Systems Engineering and Development Institute (HSSEDI) which is operated by The MITRE Corporation (MITRE). Copyright © 2006–2025, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation.

"
"
Common Weakness Enumeration
A community-developed list of SW & HW weaknesses that can become vulnerabilities


Home > CWE List > CWE-1333: Inefficient Regular Expression Complexity (4.16)  	
ID Lookup:  
Home About ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼ Search
CWE-1333: Inefficient Regular Expression Complexity
Weakness ID: 1333
Vulnerability Mapping: ALLOWED
Abstraction: Base
View customized information:
Conceptual
Operational
Mapping Friendly
Complete
Custom
 Description
The product uses a regular expression with an inefficient, possibly exponential worst-case computational complexity that consumes excessive CPU cycles.
 Extended Description
 Alternate Terms
ReDoS:	
ReDoS is an abbreviation of "Regular expression Denial of Service".
Regular Expression Denial of Service:	
While this term is attack-focused, this is commonly used to describe the weakness.
Catastrophic backtracking:	
This term is used to describe the behavior of the regular expression as a negative technical impact.
 Common Consequences
 Potential Mitigations
 Relationships
 Modes Of Introduction

Phase	Note
Implementation	A RegEx can be easy to create and read using unbounded matching characters, but the programmer might not consider the risk of excessive backtracking.
 Applicable Platforms
 Likelihood Of Exploit
High
 Demonstrative Examples
Example 1

This example attempts to check if an input string is a "sentence" [REF-1164].

(bad code)
Example Language: JavaScript 
var test_string = "Bad characters: $@#";
var bad_pattern = /^(\w+\s?)*$/i;
var result = test_string.search(bad_pattern);
The regular expression has a vulnerable backtracking clause inside (\w+\s?)*$ which can be triggered to cause a Denial of Service by processing particular phrases.

To fix the backtracking problem, backtracking is removed with the ?= portion of the expression which changes it to a lookahead and the \2 which prevents the backtracking. The modified example is:

(good code)
Example Language: JavaScript 
var test_string = "Bad characters: $@#";
var good_pattern = /^((?=(\w+))\2\s?)*$/i;
var result = test_string.search(good_pattern);
Note that [REF-1164] has a more thorough (and lengthy) explanation of everything going on within the RegEx.


Example 2

This example attempts to check if an input string is a "sentence" and is modified for Perl [REF-1164].

(bad code)
Example Language: Perl 
my $test_string = "Bad characters: \$\@\#";
my $bdrslt = $test_string;
$bdrslt =~ /^(\w+\s?)*$/i;
The regular expression has a vulnerable backtracking clause inside (\w+\s?)*$ which can be triggered to cause a Denial of Service by processing particular phrases.

To fix the backtracking problem, backtracking is removed with the ?= portion of the expression which changes it to a lookahead and the \2 which prevents the backtracking. The modified example is:

(good code)
Example Language: Perl 
my $test_string = "Bad characters: \$\@\#";
my $gdrslt = $test_string;
$gdrslt =~ /^((?=(\w+))\2\s?)*$/i;
Note that [REF-1164] has a more thorough (and lengthy) explanation of everything going on within the RegEx.


 Observed Examples
Reference	Description
CVE-2020-5243
server allows ReDOS with crafted User-Agent strings, due to overlapping capture groups that cause excessive backtracking.
CVE-2021-21317
npm package for user-agent parser prone to ReDoS due to overlapping capture groups
CVE-2019-16215
Markdown parser uses inefficient regex when processing a message, allowing users to cause CPU consumption and delay preventing processing of other messages.
CVE-2019-6785
Long string in a version control product allows DoS due to an inefficient regex.
CVE-2019-12041
Javascript code allows ReDoS via a long string due to excessive backtracking.
CVE-2015-8315
ReDoS when parsing time.
CVE-2015-8854
ReDoS when parsing documents.
CVE-2017-16021
ReDoS when validating URL.
 Memberships

Nature	Type	ID	Name
MemberOf		1416	Comprehensive Categorization: Resource Lifecycle Management
 Vulnerability Mapping Notes
Usage: ALLOWED (this CWE ID may be used to map to real-world vulnerabilities)
Reason: Acceptable-Use

Rationale:

This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities.
Comments:

Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.
 Related Attack Patterns
CAPEC-ID	Attack Pattern Name
CAPEC-492	Regular Expression Exponential Blowup
 References
[REF-1180] Scott A. Crosby. "Regular Expression Denial of Service". 2003-08. <https://web.archive.org/web/20031120114522/http://www.cs.rice.edu/~scrosby/hash/slides/USENIX-RegexpWIP.2.ppt>.
[REF-1162] Jan Goyvaerts. "Runaway Regular Expressions: Catastrophic Backtracking". 2019-12-22. <https://www.regular-expressions.info/catastrophic.html>.
[REF-1163] Adar Weidman. "Regular expression Denial of Service - ReDoS". <https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS>.
[REF-1164] Ilya Kantor. "Catastrophic backtracking". 2020-12-13. <https://javascript.info/regexp-catastrophic-backtracking>.
[REF-1165] Cristian-Alexandru Staicu and Michael Pradel. "Freezing the Web: A Study of ReDoS Vulnerabilities in JavaScript-based Web Servers". USENIX Security Symposium. 2018-07-11. <https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-staicu.pdf>.
[REF-1166] James C. Davis, Christy A. Coghlan, Francisco Servant and Dongyoon Lee. "The Impact of Regular Expression Denial of Service (ReDoS) in Practice: An Empirical Study at the Ecosystem Scale". 2018-08-01. <https://fservant.github.io/papers/Davis_Coghlan_Servant_Lee_ESECFSE18.pdf>. URL validated: 2023-04-07.
[REF-1167] James Davis. "The Regular Expression Denial of Service (ReDoS) cheat-sheet". 2020-05-23. <https://levelup.gitconnected.com/the-regular-expression-denial-of-service-redos-cheat-sheet-a78d0ed7d865>.
 Content History
 Submissions
Submission Date	Submitter	Organization
2021-01-17
(CWE 4.4, 2021-03-15)	Anonymous External Contributor	
 Modifications
Page Last Updated: November 19, 2024
 

Site Map
|
Terms of Use
|
Manage Cookies
|
Cookie Notice
|
Privacy Policy
|
Contact Us
|






Use of the Common Weakness Enumeration (CWE™) and the associated references from this website are subject to the Terms of Use. CWE is sponsored by the U.S. Department of Homeland Security (DHS) Cybersecurity and Infrastructure Security Agency (CISA) and managed by the Homeland Security Systems Engineering and Development Institute (HSSEDI) which is operated by The MITRE Corporation (MITRE). Copyright © 2006–2025, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation.

"
"
Common Weakness Enumeration
A community-developed list of SW & HW weaknesses that can become vulnerabilities


Home > CWE List > CWE-1333: Inefficient Regular Expression Complexity (4.16)  	
ID Lookup:  
Home About ▼ CWE List ▼ Mapping ▼ Top-N Lists ▼ Community ▼ News ▼ Search
CWE-1333: Inefficient Regular Expression Complexity
Weakness ID: 1333
Vulnerability Mapping: ALLOWED
Abstraction: Base
View customized information:
Conceptual
Operational
Mapping Friendly
Complete
Custom
 Description
The product uses a regular expression with an inefficient, possibly exponential worst-case computational complexity that consumes excessive CPU cycles.
 Extended Description
 Alternate Terms
ReDoS:	
ReDoS is an abbreviation of "Regular expression Denial of Service".
Regular Expression Denial of Service:	
While this term is attack-focused, this is commonly used to describe the weakness.
Catastrophic backtracking:	
This term is used to describe the behavior of the regular expression as a negative technical impact.
 Common Consequences
 Potential Mitigations
 Relationships
 Modes Of Introduction

Phase	Note
Implementation	A RegEx can be easy to create and read using unbounded matching characters, but the programmer might not consider the risk of excessive backtracking.
 Applicable Platforms
 Likelihood Of Exploit
High
 Demonstrative Examples
Example 1

This example attempts to check if an input string is a "sentence" [REF-1164].

(bad code)
Example Language: JavaScript 
var test_string = "Bad characters: $@#";
var bad_pattern = /^(\w+\s?)*$/i;
var result = test_string.search(bad_pattern);
The regular expression has a vulnerable backtracking clause inside (\w+\s?)*$ which can be triggered to cause a Denial of Service by processing particular phrases.

To fix the backtracking problem, backtracking is removed with the ?= portion of the expression which changes it to a lookahead and the \2 which prevents the backtracking. The modified example is:

(good code)
Example Language: JavaScript 
var test_string = "Bad characters: $@#";
var good_pattern = /^((?=(\w+))\2\s?)*$/i;
var result = test_string.search(good_pattern);
Note that [REF-1164] has a more thorough (and lengthy) explanation of everything going on within the RegEx.


Example 2

This example attempts to check if an input string is a "sentence" and is modified for Perl [REF-1164].

(bad code)
Example Language: Perl 
my $test_string = "Bad characters: \$\@\#";
my $bdrslt = $test_string;
$bdrslt =~ /^(\w+\s?)*$/i;
The regular expression has a vulnerable backtracking clause inside (\w+\s?)*$ which can be triggered to cause a Denial of Service by processing particular phrases.

To fix the backtracking problem, backtracking is removed with the ?= portion of the expression which changes it to a lookahead and the \2 which prevents the backtracking. The modified example is:

(good code)
Example Language: Perl 
my $test_string = "Bad characters: \$\@\#";
my $gdrslt = $test_string;
$gdrslt =~ /^((?=(\w+))\2\s?)*$/i;
Note that [REF-1164] has a more thorough (and lengthy) explanation of everything going on within the RegEx.


 Observed Examples
Reference	Description
CVE-2020-5243
server allows ReDOS with crafted User-Agent strings, due to overlapping capture groups that cause excessive backtracking.
CVE-2021-21317
npm package for user-agent parser prone to ReDoS due to overlapping capture groups
CVE-2019-16215
Markdown parser uses inefficient regex when processing a message, allowing users to cause CPU consumption and delay preventing processing of other messages.
CVE-2019-6785
Long string in a version control product allows DoS due to an inefficient regex.
CVE-2019-12041
Javascript code allows ReDoS via a long string due to excessive backtracking.
CVE-2015-8315
ReDoS when parsing time.
CVE-2015-8854
ReDoS when parsing documents.
CVE-2017-16021
ReDoS when validating URL.
 Memberships

Nature	Type	ID	Name
MemberOf		1416	Comprehensive Categorization: Resource Lifecycle Management
 Vulnerability Mapping Notes
Usage: ALLOWED (this CWE ID may be used to map to real-world vulnerabilities)
Reason: Acceptable-Use

Rationale:

This CWE entry is at the Base level of abstraction, which is a preferred level of abstraction for mapping to the root causes of vulnerabilities.
Comments:

Carefully read both the name and description to ensure that this mapping is an appropriate fit. Do not try to 'force' a mapping to a lower-level Base/Variant simply to comply with this preferred level of abstraction.
 Related Attack Patterns
CAPEC-ID	Attack Pattern Name
CAPEC-492	Regular Expression Exponential Blowup
 References
[REF-1180] Scott A. Crosby. "Regular Expression Denial of Service". 2003-08. <https://web.archive.org/web/20031120114522/http://www.cs.rice.edu/~scrosby/hash/slides/USENIX-RegexpWIP.2.ppt>.
[REF-1162] Jan Goyvaerts. "Runaway Regular Expressions: Catastrophic Backtracking". 2019-12-22. <https://www.regular-expressions.info/catastrophic.html>.
[REF-1163] Adar Weidman. "Regular expression Denial of Service - ReDoS". <https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS>.
[REF-1164] Ilya Kantor. "Catastrophic backtracking". 2020-12-13. <https://javascript.info/regexp-catastrophic-backtracking>.
[REF-1165] Cristian-Alexandru Staicu and Michael Pradel. "Freezing the Web: A Study of ReDoS Vulnerabilities in JavaScript-based Web Servers". USENIX Security Symposium. 2018-07-11. <https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-staicu.pdf>.
[REF-1166] James C. Davis, Christy A. Coghlan, Francisco Servant and Dongyoon Lee. "The Impact of Regular Expression Denial of Service (ReDoS) in Practice: An Empirical Study at the Ecosystem Scale". 2018-08-01. <https://fservant.github.io/papers/Davis_Coghlan_Servant_Lee_ESECFSE18.pdf>. URL validated: 2023-04-07.
[REF-1167] James Davis. "The Regular Expression Denial of Service (ReDoS) cheat-sheet". 2020-05-23. <https://levelup.gitconnected.com/the-regular-expression-denial-of-service-redos-cheat-sheet-a78d0ed7d865>.
 Content History
 Submissions
Submission Date	Submitter	Organization
2021-01-17
(CWE 4.4, 2021-03-15)	Anonymous External Contributor	
 Modifications
Page Last Updated: November 19, 2024
 

Site Map
|
Terms of Use
|
Manage Cookies
|
Cookie Notice
|
Privacy Policy
|
Contact Us
|






Use of the Common Weakness Enumeration (CWE™) and the associated references from this website are subject to the Terms of Use. CWE is sponsored by the U.S. Department of Homeland Security (DHS) Cybersecurity and Infrastructure Security Agency (CISA) and managed by the Homeland Security Systems Engineering and Development Institute (HSSEDI) which is operated by The MITRE Corporation (MITRE). Copyright © 2006–2025, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation.

"
Actions Performance MetricsActions Performance MetricsActions Performance MetricsActions Performance MetricsNo results matched your search.
Clear current search filters.No results matched your search.
Clear current search filters.

Your search did not match any code
However we found 9k pull requests and 4k issues that matched your search query. Alternatively try one of the tips below.

Within a repository:
repo:github/linguist
Across several:
repo:github/linguist OR repo:github/fetch
Note that we don't currently support regular expressions in the repo or org qualifiers. For more information on search syntax, see our syntax guide.
Within an organization:
org:rails
User's code:
user:mona
Note that we don't currently support regular expressions in the repo or org qualifiers. For more information on search syntax, see our syntax guide.
Sparse followed by index:
/sparse.*index/
Lines that end with return:
/return;$/
File paths matching:
path:/^\.github\/workflows\/.*\.yaml$/
Note that you'll have to escape any slashes in the regex. For more information, see our syntax guide.
Always searching within the same organization or set of repositories? Try constructing a query and click the save button in the top right corner.
For additional details about configuring, running, or shutting down the runner, please check out our product docs.

Footer
© 2025 GitHub, Inc.
Footer navigation
