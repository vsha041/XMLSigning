using System;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace CreateSignedXML
{
    /// <summary>
    ///     Following program signs the SAML XML
    ///     OpenSSL.cnf is available from here - http://web.mit.edu/crypto/openssl.cnf
    ///     OpenSSL binaries can be downloaded from here - https://indy.fulgan.com/SSL/
    ///     To generate the certificate use the following commands
    ///     openssl genrsa -out private.key 2048
    ///     openssl req -new -x509 -key private.key -out publickey.cer -days 3650 -config openssl.cnf
    ///     openssl pkcs12 -export -out SigningCertificate.pfx -inkey private.key -in publickey.cer
    ///     After importing the certificate through MMC, give the process running this code 'Read' permission
    ///     to the private key of the certificate. It is located here - C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\
    /// </summary>
    public static class Program
    {
        public static void Main(string[] args)
        {
            // load the XML
            var document = new XmlDocument
            {
                PreserveWhitespace = true
            };

            document.Load("UnsignedXML.xml");

            // load the certificate from the trusted root store
            var certificate = GetCertificate();

            // sign the XML with the above certificate
            var signedXml = SignXml(document, certificate);

            // insert the signature back inside the original XML document
            InsertSignatureElement(document, signedXml);

            document.Save("SignedXML.xml");
            
            Console.WriteLine("XML successfully signed");
            
            // verfiy that the XML is correctly signed using the public key of the original certificate
            var valid = ValidateSignedXml(document, certificate);

            Console.WriteLine($"Signed XML Valid - {valid}");
        }

        private static bool ValidateSignedXml(XmlDocument document, X509Certificate2 certificate)
        {
            var xmlNamespaceManager = GetNamespaceManager(document);
            XmlNode rootNode = document.SelectSingleNode(@"/*", xmlNamespaceManager);

            if (rootNode == null)
                throw new NullReferenceException("Root node is null");

            XmlNode signNode = rootNode.SelectSingleNode(@"ns2:Assertion/ds:Signature", xmlNamespaceManager);

            if (signNode == null)
                throw new NullReferenceException("Sign Node is null");

            if (document.DocumentElement == null)
                throw new NullReferenceException("XML not loaded");

            var verifySignedXml = new SignedXml(document.DocumentElement);
            verifySignedXml.LoadXml((XmlElement) signNode);

            bool valid = verifySignedXml.CheckSignature(certificate, false);
            return valid;
        }

        private static void InsertSignatureElement(XmlDocument document, SignedXml signedXml)
        {
            if (document.DocumentElement == null)
                throw new NullReferenceException("XML not loaded");
            
            var issuerElement = document.DocumentElement.GetElementsByTagName("Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
            
            var parentNode = issuerElement[1].ParentNode;
            if (parentNode == null)
                throw new NullReferenceException("Parent node of the XML is NULL");

            parentNode.InsertAfter(document.ImportNode(signedXml.GetXml(), true), issuerElement[1]);
        }

        private static SignedXml SignXml(XmlDocument document, X509Certificate2 certificate)
        {
            var signedXml = new SignedXml(document)
            {
                SigningKey = certificate.PrivateKey
            };
            signedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
            var reference = new Reference("");
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);
            signedXml.KeyInfo = new KeyInfo();
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(certificate, X509IncludeOption.WholeChain));
            signedXml.ComputeSignature();
            return signedXml;
        }

        private static XmlNamespaceManager GetNamespaceManager(XmlDocument document)
        {
            var @namespace = new XmlNamespaceManager(document.NameTable);
            @namespace.AddNamespace("samlp", @"urn:oasis:names:tc:SAML:2.0:protocol");
            @namespace.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            @namespace.AddNamespace("ns1", "urn:oasis:names:tc:SAML:2.0:assertion");
            @namespace.AddNamespace("ns2", "urn:oasis:names:tc:SAML:2.0:assertion");
            @namespace.AddNamespace("ds", @"http://www.w3.org/2000/09/xmldsig#");
            return @namespace;
        }

        private static X509Certificate2 GetCertificate()
        {
            var store = new X509Store(StoreName.Root);
            store.Open(OpenFlags.ReadOnly);
            try
            {
                var serial = ConfigurationManager.AppSettings["serialNumber"];
                var certificate = store.Certificates.Find(X509FindType.FindBySerialNumber, serial, true)[0];
                return certificate;
            }
            finally
            {
                store.Close();
            }
        }
    }
}