var forge = require('node-forge');
var rsa = forge.pki.rsa;
var pki = forge.pki;

var attrs = [{
  name: 'commonName',
  value: 'blacklightops.com'
}, {
  name: 'countryName',
  value: 'US'
}, {
  shortName: 'ST',
  value: 'California'
}, {
  name: 'localityName',
  value: 'Union City'
}, {
  name: 'organizationName',
  value: 'BlacklightOps'
}, {
  shortName: 'OU',
  value: 'TechOps'
}];

// generate an RSA key pair synchronously
var keypair = rsa.generateKeyPair({bits: 2048, e: 0x10001});

console.log('Creating self-signed certificate...');
var cert = forge.pki.createCertificate();
cert.publicKey = keypair.publicKey;

cert.serialNumber = '01';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

cert.setSubject(attrs);
cert.setIssuer(attrs);
cert.setExtensions([{
  name: 'basicConstraints',
  cA: true/*,
  pathLenConstraint: 4*/
}, {
  name: 'keyUsage',
  keyCertSign: true,
  digitalSignature: true,
  nonRepudiation: true,
  keyEncipherment: true,
  dataEncipherment: true
}, {
  name: 'extKeyUsage',
  serverAuth: true,
  clientAuth: true,
  codeSigning: true,
  emailProtection: true,
  timeStamping: true
}, {
  name: 'nsCertType',
  client: true,
  server: true,
  email: true,
  objsign: true,
  sslCA: true,
  emailCA: true,
  objCA: true
}, {
  name: 'subjectAltName',
  altNames: [{
    type: 6, // URI
    value: 'http://example.org/webid#me'
  }, {
    type: 7, // IP
    ip: '127.0.0.1'
  }]
}, {
  name: 'subjectKeyIdentifier'
}]);
// FIXME: add authorityKeyIdentifier extension

// self-sign certificate
cert.sign(keypair.privateKey);
console.log('Certificate created.');

// PEM-format keys and cert
var pem = {
  privateKey: forge.pki.privateKeyToPem(keypair.privateKey),
  publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
  certificate: forge.pki.certificateToPem(cert)
};

console.log('\nKey-Pair:');
console.log(pem.privateKey);
console.log(pem.publicKey);

console.log('\nCertificate:');
console.log(pem.certificate);

// creates a CA store
var caStore = pki.createCaStore();

// add a certificate to the CA store
caStore.addCertificate(cert);


console.log('Generating 1024-bit key-pair...');
var clientkeypair = forge.pki.rsa.generateKeyPair(1024);
console.log('Client Key-pair created.');

console.log('Creating certification request (CSR) ...');
var csr = forge.pki.createCertificationRequest();
csr.publicKey = clientkeypair.publicKey;
csr.setSubject([{
  name: 'commonName',
  value: 'example.org'
}, {
  name: 'countryName',
  value: 'US'
}, {
  shortName: 'ST',
  value: 'Virginia'
}, {
  name: 'localityName',
  value: 'Blacksburg'
}, {
  name: 'organizationName',
  value: 'Test'
}, {
  shortName: 'OU',
  value: 'Test'
}]);
// add optional attributes
csr.setAttributes([{
  name: 'challengePassword',
  value: 'password'
}, {
  name: 'unstructuredName',
  value: 'My company'
}]);
csr.setAttributes([{
  name: 'challengePassword',
  value: 'password'
}, {
  name: 'unstructuredName',
  value: 'My Company, Inc.'
}, {
  name: 'extensionRequest',
  extensions: [{
    name: 'subjectAltName',
    altNames: [{
      // 2 is DNS type
      type: 2,
      value: 'test.domain.com'
    }, {
      type: 2,
      value: 'other.domain.com',
    }, {
      type: 2,
      value: 'www.domain.net'
    }]
  }]
}]);
// sign certification request
csr.sign(clientkeypair.privateKey);
console.log('Certification request (CSR) created.');

var clientcert = pki.createCertificate();
clientcert.publicKey = csr.publicKey;
clientcert.serialNumber = '01';
clientcert.validity.notBefore = new Date();
clientcert.validity.notAfter = new Date();
clientcert.validity.notAfter.setFullYear(clientcert.validity.notBefore.getFullYear() + 1);
clientcert.setSubject(csr.subject.attributes);
clientcert.setIssuer(attrs);
var extensions = csr.getAttribute({name: 'extensionRequest'}).extensions;
extensions.push.apply(extensions, [{
  name: 'basicConstraints',
  cA: true
}, {
  name: 'keyUsage',
  keyCertSign: true,
  digitalSignature: true,
  nonRepudiation: true,
  keyEncipherment: true,
  dataEncipherment: true
}]);
clientcert.setExtensions(extensions);

// self-sign certificate
clientcert.sign(keypair.privateKey);

// add a certificate to the CA store
caStore.addCertificate(clientcert);

// PEM-format keys and cert
var clientpem = {
  privateKey: forge.pki.privateKeyToPem(clientkeypair.privateKey),
  publicKey: forge.pki.publicKeyToPem(clientkeypair.publicKey),
  csr: forge.pki.certificationRequestToPem(csr),
  certificate: forge.pki.certificateToPem(clientcert)
};

console.log('\nClient Key-Pair:');
console.log(clientpem.privateKey);
console.log(clientpem.publicKey);

console.log('\nClient Certification Request (CSR):');
console.log(clientpem.csr);

console.log('\nClient Certificate:');
console.log(clientpem.certificate);



