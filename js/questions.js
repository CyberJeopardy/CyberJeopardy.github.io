const questions = [
  /* Category 1 Questions */
  {
    prompt: 'Which of the following is a common type of cyber threat that spreads through email attachments or malicious links?',
    options: ['Trojan horse','Firewall','Encryption','Router'],
    correctAnswer: 'Trojan horse',
    cashPrize: 10
  },
  {
    prompt: 'What term is used to describe a type of cyber attack where an attacker disguises themselves as a trustworthy entity to deceive individuals into revealing sensitive information?',
    options: ['Virus','Phishing','Ransomware','Botnet'
],
    correctAnswer: 'Phishing',
    cashPrize: 50
  },
  {
    prompt: 'What is the term for a malicious software that encrypts files on a victims computer, rendering them inaccessible until a ransom is paid?',
    options: ['Spyware,Adware,Ransomware,Worm'],
    correctAnswer: 'Ransomware',
    cashPrize: 100
  },
  {
    prompt: 'Which of the following cybersecurity threats involves attackers gaining unauthorized access to a computer system by exploiting vulnerabilities in the software?',
    options: ['Malware','Social engineering','Denial-of-service (DoS) attack','Exploit',
],
    correctAnswer: 'Exploit',
    cashPrize: 500
  },
  {
    prompt: 'What is the term for a coordinated cyber attack in which multiple compromised computers are used to flood a target system, overwhelming it with traffic and causing it to become unavailable?',
    options: ['Botnet','Firewall','VPN','Rootkit'
],
    correctAnswer: 'Botnet',
    cashPrize: 1000
  },
  /* Category 2 Questions */
  {
    prompt: 'Which of the following is an example of a symmetric encryption algorithm?',
    options: ['RSA','Diffie-Hellman','AES','SHA-256'
],
    correctAnswer: 'AES',
    cashPrize: 10
  },
  {
    prompt: 'What is the purpose of a digital signature in cryptography?',
    options: ['To encrypt data','To ensure data integrity','To establish secure communication channels','To generate random numbers'
],
    correctAnswer: 'To ensure data integrity',
    cashPrize: 50
  },
  {
    prompt: 'Which cryptographic protocol is commonly used for secure web browsing?',
    options: ['SSH','SSL/TLS','Psec','PGP'],
    correctAnswer: 'SSH',
    cashPrize: 100
  },
  {
    prompt: 'What is the key length of a typical RSA encryption algorithm used for secure communication?',
    options: ['128 bits','256 bits','512 bits','2048 bits'
],
    correctAnswer: '2048 bits',
    cashPrize: 500
  },
  {
    prompt: 'Which of the following is NOT a type of cryptographic attack?',
    options: ['Brute-force attack','Man-in-the-middle attack','Denial-of-Service attack','Side-channel attack'],
    correctAnswer: 'Denial-of-Service attack',
    cashPrize: 1000
  },
  /* Category 3 Questions */
  {
    prompt: 'Which of the following is a common network security device used to monitor and control incoming and outgoing network traffic?',
    options: ['Firewall','Router','Switch','Modem'],
    correctAnswer: 'Firewall',
    cashPrize: 10
  },
  {
    prompt: 'What is the purpose of an intrusion detection system (IDS) in network security?',
    options: ['To encrypt network traffic','To authenticate users','To prevent denial-of-service attacks','To detect and respond to potential security breaches'
],
    correctAnswer: 'To detect and respond to potential security breaches',
    cashPrize: 50
  },
  {
    prompt: 'Which network protocol is commonly used for secure remote access to a network?',
    options: ['HTTP','FTP','SSH','SNMP'],
    correctAnswer: 'SSH',
    cashPrize: 100
  },
  {
    prompt: 'What is a common vulnerability associated with unsecured wireless networks?',
    options: ['Cross-site scripting (XSS)','SQL injection','Man-in-the-middle (MitM) attacks','Distributed denial-of-service (DDoS) attacks'],
    correctAnswer: 'Man-in-the-middle (MitM) attacks',
    cashPrize: 500
  },
  {
    prompt: 'Which of the following is NOT considered a best practice for network security?',
    options: ['Regularly updating software and firmware','Implementing strong password policies','Disabling all security features to improve network performance','Conducting regular security audits and assessments'],
    correctAnswer: 'Disabling all security features to improve network performance',
    cashPrize: 1000
  },
  /* Category 4 Questions */
  {
    prompt: 'Which of the following is a common method used for user authentication in operating systems?',
    options: [' Password-based authentication','Fingerprint recognition','Two-factor authentication','All of the above'
],
    correctAnswer: 'All of the above',
    cashPrize: 10
  },
  {
    prompt: 'What is the primary purpose of access control in operating system security?',
    options: ['To prevent unauthorized access to system resources','To ensure efficient resource allocation','To enhance system performance','To minimize system downtime'],
    correctAnswer: 'To prevent unauthorized access to system resources',
    cashPrize: 50
  },
  {
    prompt: 'Which of the following is considered a secure configuration practice for operating systems?',
    options: ['Regularly updating the operating system with security patches','Using default administrator credentials','Disabling firewall settings','Allowing guest user access to system files'],
    correctAnswer: 'Regularly updating the operating system with security patches',
    cashPrize: 100
  },
  {
    prompt: 'Which of the following is a common vulnerability in operating systems?',
    options: ['Buffer overflow','Secure Socket Layer (SSL)','Virtual Private Network (VPN)'',Intrusion Detection System (IDS)'],
    correctAnswer: 'Buffer overflow',
    cashPrize: 500
  },
  {
    prompt: 'Which of the following is an example of a rootkit, a type of malicious software that can compromise the security of an operating system?',
    options: ['Trojan horse','Firewall','Proxy server','Antivirus software'],
    correctAnswer: 'Trojan horse',
    cashPrize: 1000
  },
  /* Category 5 Questions */
  {
    prompt: 'Which of the following is an example of a common web vulnerability that allows an attacker to execute unauthorized SQL queries?',
    options: ['Cross-Site Scripting (XSS)','Buffer Overflow','SQL Injection','Denial of Service (DoS)'],
    correctAnswer: 'SQL Injection',
    cashPrize: 10
  },
  {
    prompt: 'Which secure web protocol ensures the confidentiality and integrity of data transmitted between a web browser and a web server?',
    options: ['HTTP','FTP','HTTPS','DNS'],
    correctAnswer: 'HTTPS',
    cashPrize: 50
  },
  {
    prompt: 'Which of the following is NOT a recommended secure coding practice for web applications?',
    options: ['Input validation and sanitization','Use of prepared statements for database queries','Encryption of sensitive data in transit and at rest','Storing passwords in plaintext'],
    correctAnswer: 'HTML5',
    cashPrize: 100
  },
  {
    prompt: 'What is the purpose of a Web Application Firewall (WAF)?',
    options: ['To protect web applications from common vulnerabilities and attacks','To encrypt data transmitted between a web browser and a web server','To monitor network traffic and detect potential intrusions','To authenticate and authorize users accessing a web application'
],
    correctAnswer: 'To protect web applications from common vulnerabilities and attacks',
    cashPrize: 500
  },
  {
    prompt: 'Which of the following is an example of a server-side web vulnerability that allows an attacker to execute arbitrary code on a web server?',
    options: ['Cross-Site Scripting (XSS)','Remote File Inclusion (RFI)','Cross-Site Request Forgery (CSRF)','Clickjacking'
],
    correctAnswer: 'Remote File Inclusion (RFI)',
    cashPrize: 1000
  },
  /* Digital Forensics */
  {
    prompt: 'Which of the following is an example of digital evidence?',
    options: ['Physical fingerprint','DNA sample','Email communication','Eyewitness testimony'],
    correctAnswer: 'Email communication',
    cashPrize: 10
  },
  {
    prompt: 'What is the main goal of digital forensics?',
    options: ['Preventing cyber attacks','Recovering lost data','Analyzing digital evidence','Developing encryption algorithms'
],
    correctAnswer: 'Analyzing digital evidence',
    cashPrize: 50
  },
  {
    prompt: 'Which tool is commonly used in digital forensics to collect and preserve digital evidence?',
    options: ['Antivirus software','Firewall','Encryption software','Forensic imaging tool'],
    correctAnswer: 'Forensic imaging tool',
    cashPrize: 100
  },
  {
    prompt: 'What is the process of analyzing digital evidence called?',
    options: ['Data recovery','Data encryption','Data extraction','Data analysis'
],
    correctAnswer: 'Data analysis',
    cashPrize: 500
  },
  {
    prompt: 'What is the first step in the incident response process?',
    options: ['Identifying the incident','Containing the incident','Eradicating the incident','Recovering from the incident'],
    correctAnswer: 'Identifying the incident',
    cashPrize: 1000
  },
  /* Secure Software Development */
  {
    prompt: 'Which of the following is NOT an essential principle of secure software development?',
    options: ['Input validation','Encryption','Code obfuscation','Secure code review'],
    correctAnswer: 'Code obfuscation',
    cashPrize: 10
  },
  {
    prompt: 'Which of the following is a common vulnerability that developers should be aware of during the software development lifecycle?',
    options: ['SQL injection','Cross-site scripting (XSS)','Man-in-the-middle attack','Denial of Service (DoS)'],
    correctAnswer: 'SQL injection',
    cashPrize: 50
  },
  {
    prompt: ' Which type of testing is specifically focused on uncovering security vulnerabilities in software?',
    options: ['Unit testing,Integration testing,Functional testing,Penetration testing'],
    correctAnswer: 'Penetration testing',
    cashPrize: 100
  },
  {
    prompt: 'Which secure coding practice helps prevent buffer overflow attacks?',
    options: ['Input validation','Code injection','Output encoding','Error handling'
],
    correctAnswer: 'Input validation',
    cashPrize: 500
  },
  {
    prompt: 'Which of the following is NOT a phase in the Secure Software Development Lifecycle (SSDLC)?',
    options: ['Requirements gathering','Design and architecture','Deployment and maintenance','Performance optimization'],
    correctAnswer: 'Performance optimization',
    cashPrize: 1000
  },
  /* Ethical Hacking */
  {
    prompt: 'What is the main goal of penetration testing?',
    options: ['To exploit vulnerabilities in a system','To identify and assess vulnerabilities in a system','To gain unauthorized access to a system','To create a secure network'
],
    correctAnswer: 'To identify and assess vulnerabilities in a system',
    cashPrize: 10
  },
  {
    prompt: 'Which of the following is NOT an example of a vulnerability assessment technique?',
    options: ['Network scanning','Social engineering','Penetration testing','Security audits'
],
    correctAnswer: 'Social engineering',
    cashPrize: 50
  },
  {
    prompt: 'What is the purpose of a firewall in network security?',
    options: ['To prevent unauthorized access to a network','To detect and mitigate DDoS attacks','To encrypt network traffic','To monitor network activity'
],
    correctAnswer: 'To prevent unauthorized access to a network',
    cashPrize: 100
  },
  {
    prompt: 'Which tool is commonly used for password cracking in ethical hacking?',
    options: ['Wireshark','Metasploit','John the Ripper','Nessus'
],
    correctAnswer: 'John the Ripper',
    cashPrize: 500
  },
  {
    prompt: 'Question: What is the main purpose of a reverse shell in ethical hacking?',
    options: ['To gain access to a target system','To create a backdoor for future access','To bypass firewalls and intrusion detection systems','To exploit vulnerabilities in web applications'
],
    correctAnswer: 'To create a backdoor for future access',
    cashPrize: 1000
  },
];

export default questions;
