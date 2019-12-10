using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;
using System.Xml.Linq;

using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Client;
using Microsoft.Xrm.Sdk.Discovery;

namespace BnBTechnologies.Xrm.Tourism.WebAPI
{
    public sealed class AutoRefreshSecurityToken<TProxy, TService> where TProxy : ServiceProxy<TService> where TService : class
    {
        private TProxy _proxy;

        public AutoRefreshSecurityToken(TProxy proxy)
        {
            if ((object)proxy == null)
                throw new ArgumentNullException(nameof(proxy));
            this._proxy = proxy;
        }

        public void PrepareCredentials()
        {
            if (this._proxy.ClientCredentials == null)
                return;
            switch (this._proxy.ServiceConfiguration.AuthenticationType)
            {
                case AuthenticationProviderType.ActiveDirectory:
                    this._proxy.ClientCredentials.UserName.UserName = (string)null;
                    this._proxy.ClientCredentials.UserName.Password = (string)null;
                    break;
                case AuthenticationProviderType.Federation:
                    this._proxy.ClientCredentials.Windows.ClientCredential = (NetworkCredential)null;
                    break;
            }
        }

        public void RenewTokenIfRequired()
        {
            int num1;
            if (this._proxy.SecurityTokenResponse != null)
            {
                DateTime dateTime = DateTime.UtcNow.AddMinutes(15.0);
                DateTime? expires = this._proxy.SecurityTokenResponse.Response.Lifetime.Expires;
                num1 = expires.HasValue ? (dateTime >= expires.GetValueOrDefault() ? 1 : 0) : 0;
            }
            else
                num1 = 0;
            if (num1 == 0)
                return;
            try
            {
                this._proxy.Authenticate();
            }
#pragma warning disable CS0168 // Variable is declared but never used
            catch (CommunicationException ex)
#pragma warning restore CS0168 // Variable is declared but never used
            {
                int num2;
                if (this._proxy.SecurityTokenResponse != null)
                {
                    DateTime utcNow = DateTime.UtcNow;
                    DateTime? expires = this._proxy.SecurityTokenResponse.Response.Lifetime.Expires;
                    num2 = expires.HasValue ? (utcNow >= expires.GetValueOrDefault() ? 1 : 0) : 0;
                }
                else
                    num2 = 1;
                if (num2 != 0)
                    throw;
            }
        }
    }

    internal sealed class ManagedTokenOrganizationServiceProxy : OrganizationServiceProxy
    {
        private AutoRefreshSecurityToken<OrganizationServiceProxy, IOrganizationService> _proxyManager;

        public ManagedTokenOrganizationServiceProxy(Uri serviceUri, ClientCredentials userCredentials)
          : base(serviceUri, (Uri)null, userCredentials, (ClientCredentials)null)
        {
            this._proxyManager = new AutoRefreshSecurityToken<OrganizationServiceProxy, IOrganizationService>((OrganizationServiceProxy)this);
        }

        public ManagedTokenOrganizationServiceProxy(IServiceManagement<IOrganizationService> serviceManagement, SecurityTokenResponse securityTokenRes)
          : base(serviceManagement, securityTokenRes)
        {
            this._proxyManager = new AutoRefreshSecurityToken<OrganizationServiceProxy, IOrganizationService>((OrganizationServiceProxy)this);
        }

        public ManagedTokenOrganizationServiceProxy(IServiceManagement<IOrganizationService> serviceManagement, ClientCredentials userCredentials)
          : base(serviceManagement, userCredentials)
        {
            this._proxyManager = new AutoRefreshSecurityToken<OrganizationServiceProxy, IOrganizationService>((OrganizationServiceProxy)this);
        }

        protected override void AuthenticateCore()
        {
            this._proxyManager.PrepareCredentials();
            base.AuthenticateCore();
        }

        protected override void ValidateAuthentication()
        {
            this._proxyManager.RenewTokenIfRequired();
            base.ValidateAuthentication();
        }
    }

    internal sealed class ManagedTokenDiscoveryServiceProxy : DiscoveryServiceProxy
    {
        private AutoRefreshSecurityToken<DiscoveryServiceProxy, IDiscoveryService> _proxyManager;

        public ManagedTokenDiscoveryServiceProxy(Uri serviceUri, ClientCredentials userCredentials)
          : base(serviceUri, (Uri)null, userCredentials, (ClientCredentials)null)
        {
            this._proxyManager = new AutoRefreshSecurityToken<DiscoveryServiceProxy, IDiscoveryService>((DiscoveryServiceProxy)this);
        }

        public ManagedTokenDiscoveryServiceProxy(IServiceManagement<IDiscoveryService> serviceManagement, SecurityTokenResponse securityTokenRes)
          : base(serviceManagement, securityTokenRes)
        {
            this._proxyManager = new AutoRefreshSecurityToken<DiscoveryServiceProxy, IDiscoveryService>((DiscoveryServiceProxy)this);
        }

        public ManagedTokenDiscoveryServiceProxy(IServiceManagement<IDiscoveryService> serviceManagement, ClientCredentials userCredentials)
          : base(serviceManagement, userCredentials)
        {
            this._proxyManager = new AutoRefreshSecurityToken<DiscoveryServiceProxy, IDiscoveryService>((DiscoveryServiceProxy)this);
        }

        protected override void AuthenticateCore()
        {
            this._proxyManager.PrepareCredentials();
            base.AuthenticateCore();
        }

        protected override void ValidateAuthentication()
        {
            this._proxyManager.RenewTokenIfRequired();
            base.ValidateAuthentication();
        }
    }

    internal sealed class Credential
    {
        private SecureString _userName;
        private SecureString _password;

        internal Credential(Credential.CREDENTIAL_STRUCT cred)
        {
            this._userName = this.ConvertToSecureString(cred.userName);
            int credentialBlobSize = (int)cred.credentialBlobSize;
            if ((uint)credentialBlobSize > 0U)
            {
                byte[] numArray = new byte[credentialBlobSize];
                Marshal.Copy(cred.credentialBlob, numArray, 0, credentialBlobSize);
                this._password = this.ConvertToSecureString(Encoding.Unicode.GetString(numArray));
            }
            else
                this._password = this.ConvertToSecureString(string.Empty);
        }

        public Credential(string userName, string password)
        {
            if (string.IsNullOrWhiteSpace(userName))
                throw new ArgumentNullException(nameof(userName));
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentNullException(nameof(password));
            this._userName = this.ConvertToSecureString(userName);
            this._password = this.ConvertToSecureString(password);
        }

        public string UserName
        {
            get
            {
                return this.ConvertToUnsecureString(this._userName);
            }
        }

        public string Password
        {
            get
            {
                return this.ConvertToUnsecureString(this._password);
            }
        }

        private string ConvertToUnsecureString(SecureString secret)
        {
            if (secret == null)
                return string.Empty;
            IntPtr num = IntPtr.Zero;
            try
            {
                num = Marshal.SecureStringToGlobalAllocUnicode(secret);
                return Marshal.PtrToStringUni(num);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(num);
            }
        }

        private SecureString ConvertToSecureString(string secret)
        {
            if (string.IsNullOrEmpty(secret))
                return (SecureString)null;
            SecureString secureString = new SecureString();
            foreach (char c in secret.ToCharArray())
                secureString.AppendChar(c);
            secureString.MakeReadOnly();
            return secureString;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CREDENTIAL_STRUCT
        {
            public uint flags;
            public uint type;
            public string targetName;
            public string comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME lastWritten;
            public uint credentialBlobSize;
            public IntPtr credentialBlob;
            public uint persist;
            public uint attributeCount;
            public IntPtr credAttribute;
            public string targetAlias;
            public string userName;
        }
    }

    internal static class CredentialManager
    {
        private static Dictionary<string, Credential> credentialCache = new Dictionary<string, Credential>();
        public const string TargetName = "Microsoft_CRMSDK:";

        public static Uri GetCredentialTarget(Uri target)
        {
            if ((Uri)null == target)
                throw new ArgumentNullException(nameof(target));
            return new Uri(target.GetLeftPart(UriPartial.Authority));
        }

        public static Credential ReadCredentials(string target)
        {
            Credential credential1;
            if (CredentialManager.credentialCache.TryGetValue("Microsoft_CRMSDK:" + target, out credential1))
                return credential1;
            Credential credential2;
            if (!CredentialManager.NativeMethods.CredRead("Microsoft_CRMSDK:" + target, CredentialManager.CRED_TYPE.GENERIC, 0, out credential2))
                return (Credential)null;
            CredentialManager.credentialCache["Microsoft_CRMSDK:" + target.ToString()] = credential2;
            return credential2;
        }

        public static Credential ReadWindowsCredential(Uri target)
        {
            Credential credential;
            if (!CredentialManager.NativeMethods.CredRead(target.Host, CredentialManager.CRED_TYPE.DOMAIN_PASSWORD, 0, out credential))
                throw new InvalidOperationException("Unable to read windows credentials for Uri {0}. ErrorCode {1}", (Exception)new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
            return credential;
        }

        public static void WriteCredentials(string target, Credential userCredentials, bool allowPhysicalStore)
        {
            if (string.IsNullOrWhiteSpace(target))
                throw new ArgumentNullException(nameof(target));
            if (userCredentials == null)
                throw new ArgumentNullException(nameof(userCredentials));
            CredentialManager.credentialCache["Microsoft_CRMSDK:" + target] = userCredentials;
            string s = allowPhysicalStore ? userCredentials.Password : string.Empty;
            Credential.CREDENTIAL_STRUCT credential = new Credential.CREDENTIAL_STRUCT();
            try
            {
                credential.targetName = "Microsoft_CRMSDK:" + target;
                credential.type = 1U;
                credential.userName = userCredentials.UserName;
                credential.attributeCount = 0U;
                credential.persist = 2U;
                byte[] bytes = Encoding.Unicode.GetBytes(s);
                credential.credentialBlobSize = (uint)bytes.Length;
                credential.credentialBlob = Marshal.AllocCoTaskMem(bytes.Length);
                Marshal.Copy(bytes, 0, credential.credentialBlob, bytes.Length);
                if (!CredentialManager.NativeMethods.CredWrite(ref credential, 0U))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            finally
            {
                if (IntPtr.Zero != credential.credentialBlob)
                    Marshal.FreeCoTaskMem(credential.credentialBlob);
            }
        }

        public static void DeleteCredentials(string target, bool softDelete)
        {
            if (string.IsNullOrWhiteSpace(target))
                throw new ArgumentNullException(nameof(target));
            if (softDelete)
            {
                try
                {
                    Credential credential = CredentialManager.ReadCredentials(target);
                    CredentialManager.WriteCredentials(target, new Credential(credential.UserName, string.Empty), true);
                }
                catch (Exception ex)
                {
                    throw new Exception("Error is occoured at Delete Credential.", ex);
                }
            }
            else
            {
                CredentialManager.NativeMethods.CredDelete("Microsoft_CRMSDK:" + target, 1, 0);
                CredentialManager.credentialCache.Remove("Microsoft_CRMSDK:" + target);
            }
        }

        private enum CRED_TYPE
        {
            GENERIC = 1,
            DOMAIN_PASSWORD = 2,
            DOMAIN_CERTIFICATE = 3,
            DOMAIN_VISIBLE_PASSWORD = 4,
            MAXIMUM = 5,
        }

        internal enum CRED_PERSIST : uint
        {
            SESSION = 1,
            LOCAL_MACHINE = 2,
            ENTERPRISE = 3,
        }

        private static class NativeMethods
        {
            [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CredRead(string target, CredentialManager.CRED_TYPE type, int reservedFlag, [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(CredentialManager.CredentialMarshaler))] out Credential credential);

            [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CredWrite(ref Credential.CREDENTIAL_STRUCT credential, uint flags);

            [DllImport("Advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CredFree(IntPtr cred);

            [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CredDelete(string target, int type, int flags);
        }

        private sealed class CredentialMarshaler : ICustomMarshaler
        {
            private static CredentialManager.CredentialMarshaler _instance;

            public void CleanUpManagedData(object ManagedObj)
            {
            }

            public void CleanUpNativeData(IntPtr pNativeData)
            {
                if (pNativeData == IntPtr.Zero)
                    return;
                CredentialManager.NativeMethods.CredFree(pNativeData);
            }

            public int GetNativeDataSize()
            {
                throw new NotImplementedException("The method or operation is not implemented.");
            }

            public IntPtr MarshalManagedToNative(object obj)
            {
                throw new NotImplementedException("Not implemented yet");
            }

            public object MarshalNativeToManaged(IntPtr pNativeData)
            {
                if (pNativeData == IntPtr.Zero)
                    return (object)null;
                return (object)new Credential((Credential.CREDENTIAL_STRUCT)Marshal.PtrToStructure(pNativeData, typeof(Credential.CREDENTIAL_STRUCT)));
            }

            public static ICustomMarshaler GetInstance(string cookie)
            {
                if (CredentialManager.CredentialMarshaler._instance == null)
                    CredentialManager.CredentialMarshaler._instance = new CredentialManager.CredentialMarshaler();
                return (ICustomMarshaler)CredentialManager.CredentialMarshaler._instance;
            }
        }
    }

    public class ServerConnection
    {
        public List<ServerConnection.Configuration> configurations = (List<ServerConnection.Configuration>)null;
        private ServerConnection.Configuration config = new ServerConnection.Configuration();

        public static OrganizationServiceProxy GetOrganizationProxy(ServerConnection.Configuration serverConfiguration)
        {
            if (serverConfiguration.OrganizationServiceManagement == null)
                return ServerConnection.GetProxy<IOrganizationService, OrganizationServiceProxy>(serverConfiguration);
            if (serverConfiguration.EndpointType != AuthenticationProviderType.ActiveDirectory)
                return ServerConnection.GetProxy<IOrganizationService, OrganizationServiceProxy>(serverConfiguration);
            return (OrganizationServiceProxy)new ManagedTokenOrganizationServiceProxy(serverConfiguration.OrganizationServiceManagement, serverConfiguration.Credentials);
        }

        public virtual ServerConnection.Configuration GetServerConfiguration()
        {
            bool flag;
            if (this.ReadConfigurations())
            {
                Console.Write("\n(0) Add New Server Configuration (Maximum number up to 9)\t");
                for (int index = 0; index < this.configurations.Count; ++index)
                {
                    string str = this.configurations[index].EndpointType == AuthenticationProviderType.ActiveDirectory ? (this.configurations[index].Credentials == null ? "default" : this.configurations[index].Credentials.Windows.ClientCredential.Domain + "\\" + this.configurations[index].Credentials.Windows.ClientCredential.UserName) : (this.configurations[index].Credentials == null ? "default" : this.configurations[index].Credentials.UserName.UserName);
                    Console.Write("\n({0}) Server: {1},  Org: {2},  User: {3}\t", new object[4]
                    {
                        (object) (index + 1),
                        (object) this.configurations[index].ServerAddress,
                        (object) this.configurations[index].OrganizationName,
                        (object) str
                    });
                }
                Console.WriteLine();
                Console.Write("\nSpecify the saved server configuration number (1-{0}) [{0}] : ", (object)this.configurations.Count);
                string s = Console.ReadLine();
                Console.WriteLine();
                if (s == string.Empty)
                    s = this.configurations.Count.ToString();
                int result;
                if (!int.TryParse(s, out result))
                    result = -1;
                if (result == 0)
                {
                    flag = true;
                }
                else
                {
                    if (result <= 0 || result > this.configurations.Count)
                        throw new InvalidOperationException("The specified server configuration does not exist.");
                    this.config = this.configurations[result - 1];
                    if (result != this.configurations.Count)
                    {
                        ServerConnection.Configuration configuration = this.configurations[this.configurations.Count - 1];
                        this.configurations[this.configurations.Count - 1] = this.configurations[result - 1];
                        this.configurations[result - 1] = configuration;
                    }
                    flag = false;
                }
            }
            else
                flag = true;
            if (flag)
            {
                bool ssl;
                this.config.ServerAddress = this.GetServerAddress(out ssl);
                if (string.IsNullOrWhiteSpace(this.config.ServerAddress))
                    this.config.ServerAddress = "crm.dynamics.com";
                this.config.DiscoveryUri = !this.config.ServerAddress.EndsWith(".dynamics.com", StringComparison.InvariantCultureIgnoreCase) ? (!ssl ? new Uri(string.Format("http://{0}/XRMServices/2011/Discovery.svc", (object)this.config.ServerAddress)) : new Uri(string.Format("https://{0}/XRMServices/2011/Discovery.svc", (object)this.config.ServerAddress))) : (!this.GetOrgType(this.config.ServerAddress) ? new Uri(string.Format("https://dev.{0}/XRMServices/2011/Discovery.svc", (object)this.config.ServerAddress)) : new Uri(string.Format("https://disco.{0}/XRMServices/2011/Discovery.svc", (object)this.config.ServerAddress)));
                this.config.OrganizationUri = this.GetOrganizationAddress();
                this.configurations.Add(this.config);
                for (int index = this.configurations.Count - 2; index > 0; --index)
                {
                    if (this.configurations[this.configurations.Count - 1].Equals((object)this.configurations[index]))
                        this.configurations.RemoveAt(index);
                }
                if (this.configurations.Count > 9)
                    this.configurations.RemoveAt(0);
            }
            else
                this.config.Credentials = ServerConnection.GetUserLogonCredentials(this.config);
            this.SaveConfigurations();
            return this.config;
        }

        public OrganizationDetailCollection DiscoverOrganizations(IDiscoveryService service)
        {
            if (service == null)
                throw new ArgumentNullException(nameof(service));
            RetrieveOrganizationsRequest organizationsRequest = new RetrieveOrganizationsRequest();
            return ((RetrieveOrganizationsResponse)service.Execute((DiscoveryRequest)organizationsRequest)).Details;
        }

        public OrganizationDetail FindOrganization(string orgFriendlyName, OrganizationDetail[] orgDetails)
        {
            if (string.IsNullOrWhiteSpace(orgFriendlyName))
                throw new ArgumentNullException(nameof(orgFriendlyName));
            if (orgDetails == null)
                throw new ArgumentNullException(nameof(orgDetails));
            OrganizationDetail organizationDetail = (OrganizationDetail)null;
            foreach (OrganizationDetail orgDetail in orgDetails)
            {
                if (string.Compare(orgDetail.FriendlyName, orgFriendlyName, StringComparison.InvariantCultureIgnoreCase) == 0)
                {
                    organizationDetail = orgDetail;
                    break;
                }
            }
            return organizationDetail;
        }

        public bool ReadConfigurations()
        {
            bool flag = false;
            if (this.configurations == null)
                this.configurations = new List<ServerConnection.Configuration>();
            if (System.IO.File.Exists(ServerConnection.CrmServiceHelperConstants.ServerCredentialsFile))
            {
                foreach (XElement node in XElement.Load(ServerConnection.CrmServiceHelperConstants.ServerCredentialsFile).Nodes())
                {
                    ServerConnection.Configuration configuration = new ServerConnection.Configuration();
                    XElement xelement1 = node.Element((XName)"ServerAddress");
                    if (xelement1 != null && !string.IsNullOrEmpty(xelement1.Value))
                        configuration.ServerAddress = xelement1.Value;
                    XElement xelement2 = node.Element((XName)"OrganizationName");
                    if (xelement2 != null && !string.IsNullOrEmpty(xelement2.Value))
                        configuration.OrganizationName = xelement2.Value;
                    XElement xelement3 = node.Element((XName)"DiscoveryUri");
                    if (xelement3 != null && !string.IsNullOrEmpty(xelement3.Value))
                        configuration.DiscoveryUri = new Uri(xelement3.Value);
                    XElement xelement4 = node.Element((XName)"OrganizationUri");
                    if (xelement4 != null && !string.IsNullOrEmpty(xelement4.Value))
                        configuration.OrganizationUri = new Uri(xelement4.Value);
                    XElement xelement5 = node.Element((XName)"HomeRealmUri");
                    if (xelement5 != null && !string.IsNullOrEmpty(xelement5.Value))
                        configuration.HomeRealmUri = new Uri(xelement5.Value);
                    XElement xelement6 = node.Element((XName)"EndpointType");
                    if (xelement6 != null)
                        configuration.EndpointType = this.RetrieveAuthenticationType(xelement6.Value);
                    if (node.Element((XName)"Credentials").HasElements)
                        configuration.Credentials = this.ParseInCredentials(node.Element((XName)"Credentials"), configuration.EndpointType, configuration.ServerAddress + ":" + configuration.OrganizationName + ":" + node.Element((XName)"Credentials").Element((XName)"UserName").Value);
                    XElement xelement7 = node.Element((XName)"UserPrincipalName");
                    if (xelement7 != null && !string.IsNullOrWhiteSpace(xelement7.Value))
                        configuration.UserPrincipalName = xelement7.Value;
                    this.configurations.Add(configuration);
                }
            }
            if (this.configurations.Count > 0)
                flag = true;
            return flag;
        }

        public void SaveConfigurations()
        {
            if (this.configurations == null)
                throw new NullReferenceException("No server connection configurations were found.");
            FileInfo fileInfo = new FileInfo(ServerConnection.CrmServiceHelperConstants.ServerCredentialsFile);
            if (!fileInfo.Directory.Exists)
                fileInfo.Directory.Create();
            using (FileStream fileStream = fileInfo.Open(FileMode.Create, FileAccess.Write, FileShare.None))
            {
                using (XmlTextWriter xmlTextWriter = new XmlTextWriter((Stream)fileStream, Encoding.UTF8))
                {
                    xmlTextWriter.Formatting = Formatting.Indented;
                    xmlTextWriter.WriteStartDocument();
                    xmlTextWriter.WriteStartElement("Configurations");
                    xmlTextWriter.WriteFullEndElement();
                    xmlTextWriter.WriteEndDocument();
                }
            }
            foreach (ServerConnection.Configuration configuration in this.configurations)
                this.SaveConfiguration(ServerConnection.CrmServiceHelperConstants.ServerCredentialsFile, configuration, true);
        }

        public void SaveConfiguration(string pathname, ServerConnection.Configuration config, bool append)
        {
            if (string.IsNullOrWhiteSpace(pathname))
                throw new ArgumentNullException(nameof(pathname));
            if (config == null)
                throw new ArgumentNullException(nameof(config));
            string target = config.ServerAddress + ":" + config.OrganizationName;
            if (config.Credentials != null)
            {
                switch (config.EndpointType)
                {
                    case AuthenticationProviderType.ActiveDirectory:
                        target = target + ":" + config.Credentials.Windows.ClientCredential.UserName;
                        break;
                    case AuthenticationProviderType.Federation:
                    case AuthenticationProviderType.OnlineFederation:
                        target = target + ":" + config.Credentials.UserName.UserName;
                        break;
                    default:
                        target = string.Empty;
                        break;
                }
            }
            XElement xelement1 = XElement.Load(pathname);
            XElement xelement2 = new XElement((XName)"Configuration", new object[8]
            {
                (object) new XElement((XName) "ServerAddress", (object) config.ServerAddress),
                (object) new XElement((XName) "OrganizationName", (object) config.OrganizationName),
                (object) new XElement((XName) "DiscoveryUri", config.DiscoveryUri != (Uri) null ? (object) config.DiscoveryUri.OriginalString : (object) string.Empty),
                (object) new XElement((XName) "OrganizationUri", config.OrganizationUri != (Uri) null ? (object) config.OrganizationUri.OriginalString : (object) string.Empty),
                (object) new XElement((XName) "HomeRealmUri", config.HomeRealmUri != (Uri) null ? (object) config.HomeRealmUri.OriginalString : (object) string.Empty),
                (object) this.ParseOutCredentials(config.Credentials, config.EndpointType, target),
                (object) new XElement((XName) "EndpointType", (object) config.EndpointType.ToString()),
                (object) new XElement((XName) "UserPrincipalName", config.UserPrincipalName != null ? (object) config.UserPrincipalName : (object) string.Empty)
            });
            if (append)
                xelement1.Add((object)xelement2);
            else
                xelement1.ReplaceAll((object)xelement2);
            using (XmlTextWriter xmlTextWriter = new XmlTextWriter(pathname, Encoding.UTF8))
            {
                xmlTextWriter.Formatting = Formatting.Indented;
                xelement1.Save((XmlWriter)xmlTextWriter);
            }
        }

        public static ClientCredentials GetUserLogonCredentials(ServerConnection.Configuration config)
        {
            ClientCredentials clientCredentials = new ClientCredentials();
            bool flag = config.Credentials != null;
            switch (config.EndpointType)
            {
                case AuthenticationProviderType.ActiveDirectory:
                    string domain;
                    string userName;
                    SecureString password;
                    if (flag && !string.IsNullOrWhiteSpace(config.OrganizationName))
                    {
                        domain = config.Credentials.Windows.ClientCredential.Domain;
                        userName = config.Credentials.Windows.ClientCredential.UserName;
                        if (string.IsNullOrWhiteSpace(config.Credentials.Windows.ClientCredential.Password))
                        {
                            Console.Write("\nEnter domain\\username: ");
                            Console.WriteLine(config.Credentials.Windows.ClientCredential.Domain + "\\" + config.Credentials.Windows.ClientCredential.UserName);
                            Console.Write("       Enter Password: ");
                            password = ServerConnection.ReadPassword();
                        }
                        else
                            password = config.Credentials.Windows.ClientCredential.SecurePassword;
                    }
                    else
                    {
                        if (!flag && !string.IsNullOrWhiteSpace(config.OrganizationName))
                            return (ClientCredentials)null;
                        string[] strArray;
                        do
                        {
                            Console.Write("\nEnter domain\\username: ");
                            strArray = Console.ReadLine().Split('\\');
                            if (strArray.Length == 1 && string.IsNullOrWhiteSpace(strArray[0]))
                                return (ClientCredentials)null;
                        }
                        while (strArray.Length != 2 || string.IsNullOrWhiteSpace(strArray[0]) || string.IsNullOrWhiteSpace(strArray[1]));
                        domain = strArray[0];
                        userName = strArray[1];
                        Console.Write("       Enter Password: ");
                        password = ServerConnection.ReadPassword();
                    }
                    clientCredentials.Windows.ClientCredential = password == null ? (NetworkCredential)null : new NetworkCredential(userName, password, domain);
                    break;
                case AuthenticationProviderType.Federation:
                case AuthenticationProviderType.OnlineFederation:
                    string str;
                    SecureString securePassword;
                    if (flag)
                    {
                        str = config.Credentials.UserName.UserName;
                        if (string.IsNullOrWhiteSpace(config.Credentials.UserName.Password))
                        {
                            Console.Write("\n Enter Username: ");
                            Console.WriteLine(config.Credentials.UserName.UserName);
                            Console.Write(" Enter Password: ");
                            securePassword = ServerConnection.ReadPassword();
                        }
                        else
                            securePassword = ServerConnection.ConvertToSecureString(config.Credentials.UserName.Password);
                    }
                    else
                    {
                        if (config.EndpointType == AuthenticationProviderType.OnlineFederation && config.AuthFailureCount == (short)0 && UserPrincipal.Current != null && !string.IsNullOrWhiteSpace(UserPrincipal.Current.UserPrincipalName))
                        {
                            config.UserPrincipalName = UserPrincipal.Current.UserPrincipalName;
                            return (ClientCredentials)null;
                        }
                        config.UserPrincipalName = string.Empty;
                        Console.Write("\n Enter Username: ");
                        str = Console.ReadLine();
                        if (string.IsNullOrWhiteSpace(str))
                            return (ClientCredentials)null;
                        Console.Write(" Enter Password: ");
                        securePassword = ServerConnection.ReadPassword();
                    }
                    clientCredentials.UserName.UserName = str;
                    clientCredentials.UserName.Password = ServerConnection.ConvertToUnsecureString(securePassword);
                    break;
                default:
                    clientCredentials = (ClientCredentials)null;
                    break;
            }
            return clientCredentials;
        }

        public static SecureString ReadPassword()
        {
            SecureString secureString = new SecureString();
            for (ConsoleKeyInfo consoleKeyInfo = Console.ReadKey(true); consoleKeyInfo.Key != ConsoleKey.Enter; consoleKeyInfo = Console.ReadKey(true))
            {
                if (consoleKeyInfo.Key == ConsoleKey.Backspace)
                {
                    if ((uint)secureString.Length > 0U)
                    {
                        secureString.RemoveAt(secureString.Length - 1);
                        Console.Write("\b \b");
                    }
                }
                else if (consoleKeyInfo.KeyChar >= ' ')
                {
                    secureString.AppendChar(consoleKeyInfo.KeyChar);
                    Console.Write("*");
                }
            }
            Console.WriteLine();
            Console.WriteLine();
            secureString.MakeReadOnly();
            return secureString;
        }

        public static TProxy GetProxy<TService, TProxy>(ServerConnection.Configuration currentConfig) where TService : class where TProxy : ServiceProxy<TService>
        {
            bool flag = typeof(TService).Equals(typeof(IOrganizationService));
            Uri serviceUri = flag ? currentConfig.OrganizationUri : currentConfig.DiscoveryUri;
            IServiceManagement<TService> serviceManagement = !flag || currentConfig.OrganizationServiceManagement == null ? ServiceConfigurationFactory.CreateManagement<TService>(serviceUri) : (IServiceManagement<TService>)currentConfig.OrganizationServiceManagement;
            if (flag)
            {
                if (currentConfig.OrganizationTokenResponse == null)
                    currentConfig.OrganizationServiceManagement = (IServiceManagement<IOrganizationService>)serviceManagement;
            }
            else
            {
                currentConfig.EndpointType = serviceManagement.AuthenticationType;
                currentConfig.Credentials = ServerConnection.GetUserLogonCredentials(currentConfig);
            }
            AuthenticationCredentials authenticationCredentials1 = new AuthenticationCredentials();
            if (!string.IsNullOrWhiteSpace(currentConfig.UserPrincipalName))
                authenticationCredentials1.UserPrincipalName = currentConfig.UserPrincipalName;
            else
                authenticationCredentials1.ClientCredentials = currentConfig.Credentials;
            if (currentConfig.EndpointType != AuthenticationProviderType.ActiveDirectory)
            {
                AuthenticationCredentials authenticationCredentials2 = serviceManagement.Authenticate(authenticationCredentials1);
                Type type;
                if (flag)
                {
                    currentConfig.OrganizationTokenResponse = authenticationCredentials2.SecurityTokenResponse;
                    type = typeof(ManagedTokenOrganizationServiceProxy);
                }
                else
                    type = typeof(ManagedTokenDiscoveryServiceProxy);
                return (TProxy)type.GetConstructor(new Type[2]
                {
                  typeof (IServiceManagement<TService>),
                  typeof (SecurityTokenResponse)
                }).Invoke(new object[2]
                {
                  (object) serviceManagement,
                  (object) authenticationCredentials2.SecurityTokenResponse
                });
            }
            return (TProxy)(!flag ? typeof(ManagedTokenDiscoveryServiceProxy) : typeof(ManagedTokenOrganizationServiceProxy)).GetConstructor(new Type[2]
            {
                typeof (IServiceManagement<TService>),
                typeof (ClientCredentials)
            }).Invoke(new object[2]
            {
                (object) serviceManagement,
                (object) authenticationCredentials1.ClientCredentials
            });
        }

        public static string ConvertToUnsecureString(SecureString securePassword)
        {
            if (securePassword == null)
                throw new ArgumentNullException(nameof(securePassword));
            IntPtr num = IntPtr.Zero;
            try
            {
                num = Marshal.SecureStringToGlobalAllocUnicode(securePassword);
                return Marshal.PtrToStringUni(num);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(num);
            }
        }

        public static SecureString ConvertToSecureString(string password)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));
            SecureString secureString = new SecureString();
            foreach (char c in password)
                secureString.AppendChar(c);
            secureString.MakeReadOnly();
            return secureString;
        }

        protected virtual string GetServerAddress(out bool ssl)
        {
            ssl = false;
            Console.Write("Enter a CRM server name and port [crm.dynamics.com]: ");
            string str1 = Console.ReadLine();
            if (str1.EndsWith(".dynamics.com") || string.IsNullOrWhiteSpace(str1))
            {
                ssl = true;
            }
            else
            {
                Console.Write("Is this server configured for Secure Socket Layer (https) (y/n) [n]: ");
                string str2 = Console.ReadLine();
                if (str2 == "y" || str2 == "Y")
                    ssl = true;
            }
            return str1;
        }

        protected virtual bool GetOrgType(string server)
        {
            bool flag = false;
            if (string.IsNullOrWhiteSpace(server) || server.IndexOf('.') == -1)
                return flag;
            Console.Write("Is this organization provisioned in Microsoft Office 365 (y/n) [y]: ");
            string str = Console.ReadLine();
            if (str == "y" || str == "Y" || str.Equals(string.Empty))
                flag = true;
            return flag;
        }

        protected virtual Uri GetOrganizationAddress()
        {
            using (DiscoveryServiceProxy discoveryProxy = this.GetDiscoveryProxy())
            {
                if (discoveryProxy == null)
                    throw new InvalidOperationException("An invalid server name was specified.");
                OrganizationDetailCollection detailCollection = this.DiscoverOrganizations((IDiscoveryService)discoveryProxy);
                if (detailCollection.Count > 0)
                {
                    Console.WriteLine("\nList of organizations that you belong to:");
                    for (int index = 0; index < detailCollection.Count; ++index)
                        Console.Write("\n({0}) {1} ({2})\t", (object)(index + 1), (object)detailCollection[index].FriendlyName, (object)detailCollection[index].UrlName);
                    Console.Write("\n\nSpecify an organization number (1-{0}) [1]: ", (object)detailCollection.Count);
                    string s = Console.ReadLine();
                    if (s == string.Empty)
                        s = "1";
                    int result;
                    int.TryParse(s, out result);
                    if (result <= 0 || result > detailCollection.Count)
                        throw new InvalidOperationException("The specified organization does not exist.");
                    this.config.OrganizationName = detailCollection[result - 1].FriendlyName;
                    return new Uri(detailCollection[result - 1].Endpoints[EndpointType.OrganizationService]);
                }
                Console.WriteLine("\nYou do not belong to any organizations on the specified server.");
                return new Uri(string.Empty);
            }
        }

        private DiscoveryServiceProxy GetDiscoveryProxy()
        {
            try
            {
                DiscoveryServiceProxy proxy = ServerConnection.GetProxy<IDiscoveryService, DiscoveryServiceProxy>(this.config);
                proxy.Execute((DiscoveryRequest)new RetrieveOrganizationsRequest());
                return proxy;
            }
            catch (SecurityAccessDeniedException ex)
            {
                if (string.IsNullOrWhiteSpace(this.config.UserPrincipalName) || !ex.Message.Contains("Access is denied."))
                    throw ex;
                ++this.config.AuthFailureCount;
            }
            return ServerConnection.GetProxy<IDiscoveryService, DiscoveryServiceProxy>(this.config);
        }

        private AuthenticationProviderType RetrieveAuthenticationType(string authType)
        {
            string str = authType;
            if (str == "ActiveDirectory")
                return AuthenticationProviderType.ActiveDirectory;
            if (str == "Federation")
                return AuthenticationProviderType.Federation;
            if (str == "OnlineFederation")
                return AuthenticationProviderType.OnlineFederation;
            throw new ArgumentException(string.Format("{0} is not a valid authentication type", (object)authType));
        }

        private ClientCredentials ParseInCredentials(XElement credentials, AuthenticationProviderType endpointType, string target)
        {
            ClientCredentials clientCredentials = new ClientCredentials();
            if (!credentials.HasElements)
                return (ClientCredentials)null;
            Credential credential = CredentialManager.ReadCredentials(target);
            switch (endpointType)
            {
                case AuthenticationProviderType.ActiveDirectory:
                    if (credential != null && credential.UserName.Contains("\\"))
                    {
                        string[] strArray = credential.UserName.Split('\\');
                        clientCredentials.Windows.ClientCredential = new NetworkCredential()
                        {
                            UserName = strArray[1],
                            Domain = strArray[0],
                            Password = credential.Password
                        };
                        break;
                    }
                    clientCredentials.Windows.ClientCredential = new NetworkCredential()
                    {
                        UserName = credentials.Element((XName)"UserName").Value,
                        Domain = credentials.Element((XName)"Domain").Value
                    };
                    break;
                case AuthenticationProviderType.Federation:
                case AuthenticationProviderType.OnlineFederation:
                    if (credential != null)
                    {
                        clientCredentials.UserName.UserName = credential.UserName;
                        clientCredentials.UserName.Password = credential.Password;
                        break;
                    }
                    clientCredentials.UserName.UserName = credentials.Element((XName)"UserName").Value;
                    break;
            }
            return clientCredentials;
        }

        private XElement ParseOutCredentials(ClientCredentials clientCredentials, AuthenticationProviderType endpointType, string target)
        {
            if (clientCredentials != null)
            {
                Credential credential = CredentialManager.ReadCredentials(target);
                switch (endpointType)
                {
                    case AuthenticationProviderType.ActiveDirectory:
                        if (credential == null)
                        {
                            if (!string.IsNullOrWhiteSpace(clientCredentials.Windows.ClientCredential.Password))
                                CredentialManager.WriteCredentials(target, new Credential(clientCredentials.Windows.ClientCredential.Domain + "\\" + clientCredentials.Windows.ClientCredential.UserName, clientCredentials.Windows.ClientCredential.Password), true);
                        }
                        else if (!clientCredentials.Windows.ClientCredential.Password.Equals(credential.Password))
                        {
                            CredentialManager.DeleteCredentials(target, false);
                            CredentialManager.WriteCredentials(target, new Credential(clientCredentials.Windows.ClientCredential.Domain + "\\" + clientCredentials.Windows.ClientCredential.UserName, clientCredentials.Windows.ClientCredential.Password), true);
                        }
                        return new XElement((XName)"Credentials", new object[2]
                        {
              (object) new XElement((XName) "UserName", (object) clientCredentials.Windows.ClientCredential.UserName),
              (object) new XElement((XName) "Domain", (object) clientCredentials.Windows.ClientCredential.Domain)
                        });
                    case AuthenticationProviderType.Federation:
                    case AuthenticationProviderType.OnlineFederation:
                        if (credential == null)
                        {
                            if (!string.IsNullOrWhiteSpace(clientCredentials.UserName.Password))
                                CredentialManager.WriteCredentials(target, new Credential(clientCredentials.UserName.UserName, clientCredentials.UserName.Password), true);
                        }
                        else if (!clientCredentials.UserName.Password.Equals(credential.Password))
                        {
                            CredentialManager.DeleteCredentials(target, false);
                            CredentialManager.WriteCredentials(target, new Credential(clientCredentials.UserName.UserName, clientCredentials.UserName.Password), true);
                        }
                        return new XElement((XName)"Credentials", (object)new XElement((XName)"UserName", (object)clientCredentials.UserName.UserName));
                }
            }
            return new XElement((XName)"Credentials", (object)"");
        }

        public class Configuration
        {
            public Uri HomeRealmUri = (Uri)null;
            public ClientCredentials Credentials = (ClientCredentials)null;
            internal short AuthFailureCount = 0;
            public string ServerAddress;
            public string OrganizationName;
            public Uri DiscoveryUri;
            public Uri OrganizationUri;
            public AuthenticationProviderType EndpointType;
            public string UserPrincipalName;
            internal IServiceManagement<IOrganizationService> OrganizationServiceManagement;
            internal SecurityTokenResponse OrganizationTokenResponse;

            public override bool Equals(object obj)
            {
                if (obj == null || this.GetType() != obj.GetType())
                    return false;
                ServerConnection.Configuration configuration = (ServerConnection.Configuration)obj;
                if (!this.ServerAddress.Equals(configuration.ServerAddress, StringComparison.InvariantCultureIgnoreCase) || !this.OrganizationName.Equals(configuration.OrganizationName, StringComparison.InvariantCultureIgnoreCase) || this.EndpointType != configuration.EndpointType)
                    return false;
                if (this.Credentials != null && configuration.Credentials != null)
                {
                    if (this.EndpointType == AuthenticationProviderType.ActiveDirectory)
                    {
                        if (!this.Credentials.Windows.ClientCredential.Domain.Equals(configuration.Credentials.Windows.ClientCredential.Domain, StringComparison.InvariantCultureIgnoreCase) || !this.Credentials.Windows.ClientCredential.UserName.Equals(configuration.Credentials.Windows.ClientCredential.UserName, StringComparison.InvariantCultureIgnoreCase))
                            return false;
                    }
                    else if (!this.Credentials.UserName.UserName.Equals(configuration.Credentials.UserName.UserName, StringComparison.InvariantCultureIgnoreCase))
                        return false;
                }
                return true;
            }

            public override int GetHashCode()
            {
                int num = this.ServerAddress.GetHashCode() ^ this.OrganizationName.GetHashCode() ^ this.EndpointType.GetHashCode();
                if (this.Credentials != null)
                {
                    if (this.EndpointType == AuthenticationProviderType.ActiveDirectory)
                        num = num ^ this.Credentials.Windows.ClientCredential.UserName.GetHashCode() ^ this.Credentials.Windows.ClientCredential.Domain.GetHashCode();
                    else
                        num ^= this.Credentials.UserName.UserName.GetHashCode();
                }
                return num;
            }
        }

        private static class CrmServiceHelperConstants
        {
            public static readonly string ServerCredentialsFile = Path.Combine(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CrmServer"), "Credentials.xml");
        }

    }


}