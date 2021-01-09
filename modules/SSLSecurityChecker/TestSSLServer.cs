/*
 * Command-line tool to test a SSL/TLS server for some vulnerabilities.
 * =====================================================================
 *
 * This application connects to the provided SSL/TLS server (by name and
 * port) and extracts the following information:
 * - supported versions (SSL 2.0, SSL 3.0, TLS 1.0 to 1.2)
 * - support of Deflate compression
 * - list of supported cipher suites (for each protocol version)
 * - BEAST/CRIME vulnerabilities.
 *
 * BEAST and CRIME are client-side attack, but the server can protect the
 * client by refusing to use the feature combinations which can be
 * attacked. For CRIME, the weakness is Deflate compression. For BEAST,
 * the attack conditions are more complex: it works with CBC ciphers with
 * SSL 3.0 and TLS 1.0. Hence, a server fails to protect the client against
 * BEAST if it does not enforce usage of RC4 over CBC ciphers under these
 * protocol versions, if given the choice.
 *
 * (The BEAST test considers only the cipher suites with strong
 * encryption; if the server supports none, then there are bigger
 * problems. We also assume that all clients support RC4-128; thus, the
 * server protects the client if it selects RC4-128 even if some strong
 * CBC-based ciphers are announced as supported by the client with a
 * higher preference level.)
 *
 * ----------------------------------------------------------------------
 * Copyright (c) 2012  Thomas Pornin <pornin@bolet.org>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ----------------------------------------------------------------------
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TestSSLServer
{

    public class TestSSLServer
    {

        //static void Usage()
        //{
        //    Console.WriteLine("usage: TestSSLServer servername [ port ]");
        //    Environment.Exit(1);
        //}

        //static void Main(string[] args)
        //{
        //    try
        //    {
        //        RunChecks(args);
        //    }
        //    catch (Exception e)
        //    {
        //        Console.WriteLine(e.ToString());
        //        Environment.Exit(1);
        //    }
        //}
        public delegate void OutputMessageEvent(string Output);

        public event OutputMessageEvent OutputMessage; //remove static

        public bool OutputEventSet
        {
            get
            {
                if (OutputMessage == null)
                {
                    return false;
                }
                else
                {
                    return true;
                }
            }
        }

        public void DebugOutput(string Output)
        {
            if (OutputMessage != null)
            {
                try
                {
                    OutputMessage(Output+"\n");
                }
                catch
                { }
            }
        }

        bool InitDone = false;

        public string RunChecks(string name, string sslport )
        {
            if (!InitDone)
            {
                InitCipherSuites();
            }
            InitDone = true;
            //if (args.Length == 0 || args.Length > 2)
            //{
            //    Usage();
            //}
            //string name = args[0];

            StringBuilder output = new StringBuilder();

            int port = Int32.Parse(sslport);
            //if (args.Length == 2)
            //{
            //    try
            //    {
            //        port = Int32.Parse(args[1]);
            //    }
            //    catch (Exception)
            //    {
            //        //Usage();
            //    }
            //    if (port <= 0 || port > 65535)
            //    {
            //        //Usage();
            //    }
            //}

            IDictionary<int, int> sv = new SortedDictionary<int, int>();
            bool compress = false;

            /* SSL_PROTOCOL_VERSION_SSL3 = 0x0300
             * SSL_PROTOCOL_VERSION_TLS1 = 0x0301
             * SSL_PROTOCOL_VERSION_TLS1_1 = 0x0302
             * SSL_PROTOCOL_VERSION_TLS1_2 = 0x0303 
             */
            string protoVersion;

            for (int v = 0x0300; v <= 0x0303; v++)
            {
                switch (v)
                {
                    case 0x0300:
                        protoVersion = "SSL v3.0";
                        break;
                    case 0x0301:
                        protoVersion = "TLS v1.0";
                        break;
                    case 0x0302:
                        protoVersion = "TLS v1.1";
                        break;
                    case 0x0303:
                        protoVersion = "TLS v1.2";
                        break;
                    default:
                        protoVersion = "";
                        break;
                }

                DebugOutput("[+INFO] Sending ServerHello for " + protoVersion);
             
                ServerHello sh = Connect(name, port, v, CIPHER_SUITES.Keys);

                if (sh == null)
                {
                    DebugOutput("[+INFO] Server did not respond for " + protoVersion);
                    continue;
                }
                
                AddToSet(sv, sh.protoVersion);
                if (sh.compression == 1)
                {
                    compress = true;
                    DebugOutput("[+FINDING] Server supports Deflate compression and may be vulnerable to CRIME attack");
                }
            }

            DebugOutput("[+INFO] Sending ServerHello for SSL v2.0");
            ServerHelloSSLv2 sh2 = ConnectV2(name, port);
            if (sh2 != null)
            {
                AddToSet(sv, 0x0200);
            }

            if (sv.Count == 0)
            {
                output.AppendLine("No SSL/TLS server at " + name + ":" + port);
                //Environment.Exit(1);
                return output.ToString();
            }

            output.AppendLine("Supported versions:");
            foreach (int v in sv.Keys)
            {
                output.Append(" ");
                output.Append(VersionString(v));
                DebugOutput("[+FINDING] Server Supports " + VersionString(v));
            }
            output.AppendLine("");
            output.AppendLine("Deflate compression: " + (compress ? "YES" : "no"));

            output.AppendLine("Supported cipher suites (ORDER IS NOT SIGNIFICANT):");
            IDictionary<int, int> lastSuppCS = null;
            IDictionary<int, IDictionary<int, int>> suppCS = new SortedDictionary<int, IDictionary<int, int>>();
            IDictionary<string, int> certID = new SortedDictionary<string, int>();

            if (sh2 != null)
            {
                output.AppendLine("  " + VersionString(0x0200));
                IDictionary<int, int> vc2 = new SortedDictionary<int, int>();
                foreach (int c in sh2.cipherSuites)
                {
                    AddToSet(vc2, c);
                }
                foreach (int c in vc2.Keys)
                {
                    output.AppendLine("     " + CipherSuiteString(c));
                }
                suppCS.Add(0x0200, vc2);
                if (sh2.serverCertName != null)
                {
                    AddToSet(certID, sh2.serverCertHash + ": " + sh2.serverCertName);
                }
            }

            foreach (int v in sv.Keys)
            {
                if (v == 0x0200)
                {
                    continue;
                }
                IDictionary<int, int> vsc = SupportedSuites(name, port, v, certID);
                suppCS.Add(v, vsc);
                if (!SameSetInt(lastSuppCS, vsc))
                {
                    output.AppendLine("  " + VersionString(v));
                    foreach (int c in vsc.Keys)
                    {
                        output.AppendLine("     " + CipherSuiteString(c));
                        //DebugOutput("[+FINDING] For " + VersionString(v) + " " + CipherSuiteString(c) + " Cipher supported ");
                    }
                    lastSuppCS = vsc;
                }
                else
                {
                    output.AppendLine("  (" + VersionString(v) + ": idem)");
                }
            }
            output.AppendLine("----------------------");
            if (certID.Count == 0)
            {
                output.AppendLine("No server certificate !");
            }
            else
            {
                output.AppendLine("Server certificate(s):");
                foreach (string cc in certID.Keys)
                {
                    output.AppendLine("  " + cc);
                }
            }
            output.AppendLine("----------------------");
            int agMaxStrength = STRONG;
            int agMinStrength = STRONG;
            bool vulnBEAST = false;
            foreach (int v in sv.Keys)
            {
                IDictionary<int, int> vsc = suppCS[v];
                agMaxStrength = Math.Min(
                    MaxStrength(vsc), agMaxStrength);
                agMinStrength = Math.Min(
                    MinStrength(vsc), agMinStrength);
                if (!vulnBEAST)
                {
                    vulnBEAST = TestBEAST(name, port, v, vsc);
                    DebugOutput((vulnBEAST ? "[+FINDING] Server appears to be vulnerable to BEAST attack as it supports CBC mode ciphers"
                        : "[+INFO] Server does not appear to be vulnerable to BEAST attack"));
                }
            }
            output.AppendLine("Minimal encryption strength:     "
                + StrengthString(agMinStrength));
            output.AppendLine("Achievable encryption strength:  "
                + StrengthString(agMaxStrength));
            output.AppendLine("BEAST status: "
                + (vulnBEAST ? "vulnerable" : "protected"));
            output.AppendLine("CRIME status: "
                + (compress ? "vulnerable" : "protected"));
            //Console.WriteLine(output.ToString());
            return output.ToString();
        }

        void AddToSet<T>(IDictionary<T, int> s, T val)
        {
            if (!s.ContainsKey(val))
            {
                s.Add(val, 0);
            }
        }

        bool IsInSet<T>(IDictionary<T, int> s, T val)
        {
            return s.ContainsKey(val);
        }

        bool SameSetInt(
            IDictionary<int, int> s1, IDictionary<int, int> s2)
        {
            if (s1 == s2)
            {
                return true;
            }
            if (s1 == null || s2 == null)
            {
                return false;
            }
            if (s1.Count != s2.Count)
            {
                return false;
            }
            foreach (int k in s1.Keys)
            {
                if (!s2.ContainsKey(k))
                {
                    return false;
                }
            }
            return true;
        }

        /*
         * Get cipher suites supported by the server. This is done by
         * repeatedly contacting the server, each time removing from our
         * list of supported suites the suite which the server just
         * selected. We keep on until the server can no longer respond
         * to us with a ServerHello.
         */
        IDictionary<int, int> SupportedSuites(
            string name, int port, int version,
            IDictionary<string, int> serverCertID)
        {
            IDictionary<int, int> cs = new SortedDictionary<int, int>();
            foreach (int k in CIPHER_SUITES.Keys)
            {
                AddToSet(cs, k);
            }
            IDictionary<int, int> rs = new SortedDictionary<int, int>();
            for (; ; )
            {
                ServerHello sh = Connect(name, port, version, cs.Keys);
                if (sh == null)
                {
                    break;
                }

                if (!IsInSet(cs, sh.cipherSuite))
                {
                    DebugOutput(String.Format("[ERR: server wants to use"
                        + " cipher suite 0x{0:X4} which client"
                        + " did not announce]", sh.cipherSuite));
                    break;
                }
                cs.Remove(sh.cipherSuite);
                AddToSet(rs, sh.cipherSuite);

                if (version == 0x0200)
                {
                    DebugOutput("[+FINDING] Cipher " + CipherSuiteStringV2(sh.cipherSuite) + " is supported for " + VersionString(version));
                }
                else 
                {
                    DebugOutput("[+FINDING] Cipher " + CipherSuiteString(sh.cipherSuite) + " is supported for " + VersionString(version));
                }

                if (sh.serverCertName != null)
                {
                    AddToSet(serverCertID, sh.serverCertHash + ": " + sh.serverCertName);
                }
            }
            return rs;
        }

        int MinStrength(IDictionary<int, int> supp)
        {
            int m = STRONG;
            foreach (int suite in supp.Keys)
            {
                CipherSuite cs = CIPHER_SUITES[suite];
                if (cs == null)
                {
                    continue;
                }
                if (cs.strength < m)
                {
                    m = cs.strength;
                }
            }
            return m;
        }

        int MaxStrength(IDictionary<int, int> supp)
        {
            int m = CLEAR;
            foreach (int suite in supp.Keys)
            {
                CipherSuite cs = CIPHER_SUITES[suite];
                if (cs == null)
                {
                    continue;
                }
                if (cs.strength > m)
                {
                    m = cs.strength;
                }
            }
            return m;
        }

        bool TestBEAST(string name, int port, int version, IDictionary<int, int> supp)
        {
            DebugOutput("[+INFO] Testing if the server is vulnerable to BEAST attack");
            /*
             * TLS 1.1+ is not vulnerable to BEAST.
             * We do not test SSLv2 either.
             */
            if (version < 0x0300 || version > 0x0301)
            {
                return false;
            }

            /*
             * BEAST attack works if the server allows the client to
             * use a CBC cipher. Existing clients also supports RC4,
             * so we consider that a server protects the clients if
             * it chooses RC4 over CBC streams when given the choice.
             * We only consider strong cipher suites here.
             */
            IList<int> strongCBC = new List<int>();
            IList<int> strongStream = new List<int>();
            foreach (int suite in supp.Keys)
            {
                CipherSuite cs = CIPHER_SUITES[suite];
                if (cs == null)
                {
                    continue;
                }
                if (cs.strength < STRONG)
                {
                    continue;
                }
                if (cs.isCBC)
                {
                    strongCBC.Add(suite);
                }
                else
                {
                    strongStream.Add(suite);
                }
            }
            if (strongCBC.Count == 0)
            {
                return false;
            }
            if (strongStream.Count == 0)
            {
                return true;
            }
            IList<int> ns = new List<int>();
            foreach (int suite in strongCBC)
            {
                ns.Add(suite);
            }
            foreach (int suite in strongStream)
            {
                ns.Add(suite);
            }
            ServerHello sh = Connect(name, port, version, ns);
            return CIPHER_SUITES[sh.cipherSuite].isCBC;
        }

        string VersionString(int version)
        {
            if (version == 0x0200)
            {
                return "SSLv2";
            }
            else if (version == 0x0300)
            {
                return "SSLv3";
            }
            else if (((uint)version >> 8) == 0x03)
            {
                return "TLSv1." + ((version & 0xFF) - 1);
            }
            else
            {
                return String.Format(
                    "UNKNOWN_VERSION:0x{0:X4}", version);
            }
        }

        /*
         * Connect to the server, send a ClientHello, and decode the
         * response (ServerHello). On error, null is returned.
         */
        ServerHello Connect(string name, int port, int version, ICollection<int> cipherSuites)
        {
            NetworkStream ns = null;
            try
            {
                try
                {
                    TcpClient tc = new TcpClient(name, port);
                    ns = tc.GetStream();
                }
                catch (Exception e)
                {
                    DebugOutput("could not connect to " + name + ":" + port);
                    DebugOutput(e.ToString());
                    return null;
                }
                byte[] ch = MakeClientHello(version, cipherSuites);
                SSLRecord rec = new SSLRecord(ns);
                rec.SetOutType(M.HANDSHAKE);
                rec.SetOutVersion(version);
                rec.Write(ch);
                rec.Flush();
                return new ServerHello(rec);
            }
            catch (Exception)
            {
                // ignored
            }
            finally
            {
                try
                {
                    if (ns != null)
                    {
                        ns.Close();
                    }
                }
                catch (Exception)
                {
                    // ignored
                }
            }
            return null;
        }

        /*
         * Connect to the server, send a SSLv2 CLIENT-HELLO, and decode
         * the response (SERVER-HELLO). On error, null is returned.
         */
        ServerHelloSSLv2 ConnectV2(string name, int port)
        {
            NetworkStream ns = null;
            try
            {
                try
                {
                    TcpClient tc = new TcpClient(name, port);
                    ns = tc.GetStream();
                }
                catch (Exception e)
                {
                    DebugOutput("could not connect to " + name + ":" + port);
                    DebugOutput(e.ToString());
                    return null;
                }
                ns.Write(M.SSL2_CLIENT_HELLO, 0, M.SSL2_CLIENT_HELLO.Length);
                return new ServerHelloSSLv2(ns);
            }
            catch (Exception)
            {
                // ignored
            }
            finally
            {
                try
                {
                    if (ns != null)
                    {
                        ns.Close();
                    }
                }
                catch (Exception)
                {
                    // ignored
                }
            }
            return null;
        }

        readonly RandomNumberGenerator RNG = new RNGCryptoServiceProvider();

        /*
         * Build a ClientHello message, with the specified maximum
         * supported version, and list of cipher suites.
         */
        byte[] MakeClientHello(int version, ICollection<int> cipherSuites)
        {
            MemoryStream b = new MemoryStream();

            /*
             * Message header:
             *   message type: one byte (1 = "ClientHello")
             *   message length: three bytes (this will be adjusted
             *   at the end of this method).
             */
            b.WriteByte(1);
            b.WriteByte(0);
            b.WriteByte(0);
            b.WriteByte(0);

            /*
             * The maximum version that we intend to support.
             */
            b.WriteByte((byte)(version >> 8));
            b.WriteByte((byte)version);

            /*
             * The client random has length 32 bytes, but begins with
             * the client's notion of the current time, over 32 bits
             * (seconds since 1970/01/01 00:00:00 UTC, not counting
             * leap seconds).
             */
            byte[] rand = new byte[32];
            RNG.GetBytes(rand);
            M.Enc32be((int)(M.CurrentTimeMillis() / 1000), rand, 0);
            b.Write(rand, 0, rand.Length);

            /*
             * We send an empty session ID.
             */
            b.WriteByte(0);

            /*
             * The list of cipher suites (list of 16-bit values; the
             * list length in bytes is written first).
             */
            int num = cipherSuites.Count;
            byte[] cs = new byte[2 + num * 2];
            M.Enc16be(num * 2, cs, 0);
            int j = 2;
            foreach (int s in cipherSuites)
            {
                M.Enc16be(s, cs, j);
                j += 2;
            }
            b.Write(cs, 0, cs.Length);

            /*
             * Compression methods: we claim to support Deflate (1)
             * and the standard no-compression (0), with Deflate
             * being preferred.
             */
            b.WriteByte(2);
            b.WriteByte(1);
            b.WriteByte(0);

            /*
             * If we had extensions to add, they would go here.
             */

            /*
             * We now get the message as a blob. The message length
             * must be adjusted in the header.
             */
            byte[] msg = b.ToArray();
            M.Enc24be(msg.Length - 4, msg, 1);
            return msg;
        }

        readonly IDictionary<int, CipherSuite> CIPHER_SUITES =
            new SortedDictionary<int, CipherSuite>();

        const int CLEAR = 0; // no encryption
        const int WEAK = 1; // weak encryption: 40-bit key
        const int MEDIUM = 2; // medium encryption: 56-bit key
        const int STRONG = 3; // strong encryption

        string StrengthString(int strength)
        {
            switch (strength)
            {
                case CLEAR: return "no encryption";
                case WEAK: return "weak encryption (40-bit)";
                case MEDIUM: return "medium encryption (56-bit)";
                case STRONG: return "strong encryption (96-bit or more)";
                default:
                    throw new Exception("strange strength: " + strength);
            }
        }

        string CipherSuiteString(int suite)
        {
            CipherSuite cs = CIPHER_SUITES[suite];
            if (cs == null)
            {
                return String.Format("UNKNOWN_SUITE:0x{0:X4}", suite);
            }
            else
            {
                return cs.name;
            }
        }

        string CipherSuiteStringV2(int suite)
        {
            CipherSuite cs = CIPHER_SUITES[suite];
            if (cs == null)
            {
                return String.Format(
                    "UNKNOWN_SUITE:{0:X2},{0:X2},{0:X2}",
                    suite >> 16, (suite >> 8) & 0xFF, suite & 0xFF);
            }
            else
            {
                return cs.name;
            }
        }

        void MakeCS(int suite, String name, bool isCBC, int strength)
        {
            CipherSuite cs = new CipherSuite();
            cs.suite = suite;
            cs.name = name;
            cs.isCBC = isCBC;
            cs.strength = strength;
            CIPHER_SUITES.Add(suite, cs);

            /*
             * Consistency test: the strength and CBC status can normally
             * be inferred from the name itself.
             */
            bool inferredCBC = name.Contains("_CBC_");
            int inferredStrength;
            if (name.Contains("_NULL_"))
            {
                inferredStrength = CLEAR;
            }
            else if (name.Contains("DES40") || name.Contains("_40_")
              || name.Contains("EXPORT40"))
            {
                inferredStrength = WEAK;
            }
            else if ((name.Contains("_DES_") || name.Contains("DES_64"))
              && !name.Contains("DES_192"))
            {
                inferredStrength = MEDIUM;
            }
            else
            {
                inferredStrength = STRONG;
            }
            if (inferredStrength != strength || inferredCBC != isCBC)
            {
                throw new Exception("wrong classification: " + name);
            }
        }

        void N(int suite, string name)
        {
            MakeCS(suite, name, false, CLEAR);
        }

        void S4(int suite, string name)
        {
            MakeCS(suite, name, false, WEAK);
        }

        void S8(int suite, string name)
        {
            MakeCS(suite, name, false, STRONG);
        }

        void B4(int suite, string name)
        {
            MakeCS(suite, name, true, WEAK);
        }

        void B5(int suite, string name)
        {
            MakeCS(suite, name, true, MEDIUM);
        }

        void B8(int suite, string name)
        {
            MakeCS(suite, name, true, STRONG);
        }

        void InitCipherSuites()
        {
            DebugOutput("[+INFO] Initialising Cipher Suites");

            /*
             * SSLv2 cipher suites.
             */
            S8(0x010080, "RC4_128_WITH_MD5");
            S4(0x020080, "RC4_128_EXPORT40_WITH_MD5");
            B8(0x030080, "RC2_128_CBC_WITH_MD5");
            B4(0x040080, "RC2_128_CBC_EXPORT40_WITH_MD5");
            B8(0x050080, "IDEA_128_CBC_WITH_MD5");
            B5(0x060040, "DES_64_CBC_WITH_MD5");
            B8(0x0700C0, "DES_192_EDE3_CBC_WITH_MD5");

            /*
             * Original suites (SSLv3, TLS 1.0).
             */
            N(0x0000, "NULL_WITH_NULL_NULL");
            N(0x0001, "RSA_WITH_NULL_MD5");
            N(0x0002, "RSA_WITH_NULL_SHA");
            S4(0x0003, "RSA_EXPORT_WITH_RC4_40_MD5");
            S8(0x0004, "RSA_WITH_RC4_128_MD5");
            S8(0x0005, "RSA_WITH_RC4_128_SHA");
            B4(0x0006, "RSA_EXPORT_WITH_RC2_CBC_40_MD5");
            B8(0x0007, "RSA_WITH_IDEA_CBC_SHA");
            B4(0x0008, "RSA_EXPORT_WITH_DES40_CBC_SHA");
            B5(0x0009, "RSA_WITH_DES_CBC_SHA");
            B8(0x000A, "RSA_WITH_3DES_EDE_CBC_SHA");
            B4(0x000B, "DH_DSS_EXPORT_WITH_DES40_CBC_SHA");
            B5(0x000C, "DH_DSS_WITH_DES_CBC_SHA");
            B8(0x000D, "DH_DSS_WITH_3DES_EDE_CBC_SHA");
            B4(0x000E, "DH_RSA_EXPORT_WITH_DES40_CBC_SHA");
            B5(0x000F, "DH_RSA_WITH_DES_CBC_SHA");
            B8(0x0010, "DH_RSA_WITH_3DES_EDE_CBC_SHA");
            B4(0x0011, "DHE_DSS_EXPORT_WITH_DES40_CBC_SHA");
            B5(0x0012, "DHE_DSS_WITH_DES_CBC_SHA");
            B8(0x0013, "DHE_DSS_WITH_3DES_EDE_CBC_SHA");
            B4(0x0014, "DHE_RSA_EXPORT_WITH_DES40_CBC_SHA");
            B5(0x0015, "DHE_RSA_WITH_DES_CBC_SHA");
            B8(0x0016, "DHE_RSA_WITH_3DES_EDE_CBC_SHA");
            S4(0x0017, "DH_anon_EXPORT_WITH_RC4_40_MD5");
            S8(0x0018, "DH_anon_WITH_RC4_128_MD5");
            B4(0x0019, "DH_anon_EXPORT_WITH_DES40_CBC_SHA");
            B5(0x001A, "DH_anon_WITH_DES_CBC_SHA");
            B8(0x001B, "DH_anon_WITH_3DES_EDE_CBC_SHA");

            /*
             * FORTEZZA suites (SSLv3 only; see RFC 6101).
             */
            N(0x001C, "FORTEZZA_KEA_WITH_NULL_SHA");
            B8(0x001D, "FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA");

            /* This one is deactivated since it conflicts with
               one of the Kerberos cipher suites.
            S8(0x001E, "FORTEZZA_KEA_WITH_RC4_128_SHA"      );
            */

            /*
             * Kerberos cipher suites (RFC 2712).
             */
            B5(0x001E, "KRB5_WITH_DES_CBC_SHA");
            B8(0x001F, "KRB5_WITH_3DES_EDE_CBC_SHA");
            S8(0x0020, "KRB5_WITH_RC4_128_SHA");
            B8(0x0021, "KRB5_WITH_IDEA_CBC_SHA");
            B5(0x0022, "KRB5_WITH_DES_CBC_MD5");
            B8(0x0023, "KRB5_WITH_3DES_EDE_CBC_MD5");
            S8(0x0024, "KRB5_WITH_RC4_128_MD5");
            B8(0x0025, "KRB5_WITH_IDEA_CBC_MD5");
            B4(0x0026, "KRB5_EXPORT_WITH_DES_CBC_40_SHA");
            B4(0x0027, "KRB5_EXPORT_WITH_RC2_CBC_40_SHA");
            S4(0x0028, "KRB5_EXPORT_WITH_RC4_40_SHA");
            B4(0x0029, "KRB5_EXPORT_WITH_DES_CBC_40_MD5");
            B4(0x002A, "KRB5_EXPORT_WITH_RC2_CBC_40_MD5");
            S4(0x002B, "KRB5_EXPORT_WITH_RC4_40_MD5");

            /*
             * Pre-shared key, no encryption cipher suites (RFC 4785).
             */
            N(0x002C, "PSK_WITH_NULL_SHA");
            N(0x002D, "DHE_PSK_WITH_NULL_SHA");
            N(0x002E, "RSA_PSK_WITH_NULL_SHA");

            /*
             * AES-based suites (TLS 1.1).
             */
            B8(0x002F, "RSA_WITH_AES_128_CBC_SHA");
            B8(0x0030, "DH_DSS_WITH_AES_128_CBC_SHA");
            B8(0x0031, "DH_RSA_WITH_AES_128_CBC_SHA");
            B8(0x0032, "DHE_DSS_WITH_AES_128_CBC_SHA");
            B8(0x0033, "DHE_RSA_WITH_AES_128_CBC_SHA");
            B8(0x0034, "DH_anon_WITH_AES_128_CBC_SHA");
            B8(0x0035, "RSA_WITH_AES_256_CBC_SHA");
            B8(0x0036, "DH_DSS_WITH_AES_256_CBC_SHA");
            B8(0x0037, "DH_RSA_WITH_AES_256_CBC_SHA");
            B8(0x0038, "DHE_DSS_WITH_AES_256_CBC_SHA");
            B8(0x0039, "DHE_RSA_WITH_AES_256_CBC_SHA");
            B8(0x003A, "DH_anon_WITH_AES_256_CBC_SHA");

            /*
             * Suites with SHA-256 (TLS 1.2).
             */
            N(0x003B, "RSA_WITH_NULL_SHA256");
            B8(0x003C, "RSA_WITH_AES_128_CBC_SHA256");
            B8(0x003D, "RSA_WITH_AES_256_CBC_SHA256");
            B8(0x003E, "DH_DSS_WITH_AES_128_CBC_SHA256");
            B8(0x003F, "DH_RSA_WITH_AES_128_CBC_SHA256");
            B8(0x0040, "DHE_DSS_WITH_AES_128_CBC_SHA256");
            B8(0x0067, "DHE_RSA_WITH_AES_128_CBC_SHA256");
            B8(0x0068, "DH_DSS_WITH_AES_256_CBC_SHA256");
            B8(0x0069, "DH_RSA_WITH_AES_256_CBC_SHA256");
            B8(0x006A, "DHE_DSS_WITH_AES_256_CBC_SHA256");
            B8(0x006B, "DHE_RSA_WITH_AES_256_CBC_SHA256");
            B8(0x006C, "DH_anon_WITH_AES_128_CBC_SHA256");
            B8(0x006D, "DH_anon_WITH_AES_256_CBC_SHA256");

            /*
             * Camellia cipher suites (RFC 5932).
             */
            B8(0x0041, "RSA_WITH_CAMELLIA_128_CBC_SHA");
            B8(0x0042, "DH_DSS_WITH_CAMELLIA_128_CBC_SHA");
            B8(0x0043, "DH_RSA_WITH_CAMELLIA_128_CBC_SHA");
            B8(0x0044, "DHE_DSS_WITH_CAMELLIA_128_CBC_SHA");
            B8(0x0045, "DHE_RSA_WITH_CAMELLIA_128_CBC_SHA");
            B8(0x0046, "DH_anon_WITH_CAMELLIA_128_CBC_SHA");
            B8(0x0084, "RSA_WITH_CAMELLIA_256_CBC_SHA");
            B8(0x0085, "DH_DSS_WITH_CAMELLIA_256_CBC_SHA");
            B8(0x0086, "DH_RSA_WITH_CAMELLIA_256_CBC_SHA");
            B8(0x0087, "DHE_DSS_WITH_CAMELLIA_256_CBC_SHA");
            B8(0x0088, "DHE_RSA_WITH_CAMELLIA_256_CBC_SHA");
            B8(0x0089, "DH_anon_WITH_CAMELLIA_256_CBC_SHA");

            /*
             * Unsorted (yet), from the IANA TLS registry:
             * http://www.iana.org/assignments/tls-parameters/
             */
            S8(0x008A, "TLS_PSK_WITH_RC4_128_SHA");
            B8(0x008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA");
            B8(0x008C, "TLS_PSK_WITH_AES_128_CBC_SHA");
            B8(0x008D, "TLS_PSK_WITH_AES_256_CBC_SHA");
            S8(0x008E, "TLS_DHE_PSK_WITH_RC4_128_SHA");
            B8(0x008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA");
            B8(0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA");
            B8(0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA");
            S8(0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA");
            B8(0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA");
            B8(0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA");
            B8(0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA");
            B8(0x0096, "TLS_RSA_WITH_SEED_CBC_SHA");
            B8(0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA");
            B8(0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA");
            B8(0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA");
            B8(0x009A, "TLS_DHE_RSA_WITH_SEED_CBC_SHA");
            B8(0x009B, "TLS_DH_anon_WITH_SEED_CBC_SHA");
            S8(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256");
            S8(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384");
            S8(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256");
            S8(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384");
            S8(0x00A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256");
            S8(0x00A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384");
            S8(0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256");
            S8(0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384");
            S8(0x00A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256");
            S8(0x00A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384");
            S8(0x00A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256");
            S8(0x00A7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384");
            S8(0x00A8, "TLS_PSK_WITH_AES_128_GCM_SHA256");
            S8(0x00A9, "TLS_PSK_WITH_AES_256_GCM_SHA384");
            S8(0x00AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256");
            S8(0x00AB, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384");
            S8(0x00AC, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256");
            S8(0x00AD, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384");
            B8(0x00AE, "TLS_PSK_WITH_AES_128_CBC_SHA256");
            B8(0x00AF, "TLS_PSK_WITH_AES_256_CBC_SHA384");
            N(0x00B0, "TLS_PSK_WITH_NULL_SHA256");
            N(0x00B1, "TLS_PSK_WITH_NULL_SHA384");
            B8(0x00B2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256");
            B8(0x00B3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384");
            N(0x00B4, "TLS_DHE_PSK_WITH_NULL_SHA256");
            N(0x00B5, "TLS_DHE_PSK_WITH_NULL_SHA384");
            B8(0x00B6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256");
            B8(0x00B7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384");
            N(0x00B8, "TLS_RSA_PSK_WITH_NULL_SHA256");
            N(0x00B9, "TLS_RSA_PSK_WITH_NULL_SHA384");
            B8(0x00BA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256");
            B8(0x00BB, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256");
            B8(0x00BC, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256");
            B8(0x00BD, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256");
            B8(0x00BE, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256");
            B8(0x00BF, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256");
            B8(0x00C0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256");
            B8(0x00C1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256");
            B8(0x00C2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256");
            B8(0x00C3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256");
            B8(0x00C4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256");
            B8(0x00C5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256");
            /* This one is a fake cipher suite which marks a
               renegotiation.
            N(0x00FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"                );
            */
            N(0xC001, "TLS_ECDH_ECDSA_WITH_NULL_SHA");
            S8(0xC002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA");
            B8(0xC003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA");
            B8(0xC004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA");
            B8(0xC005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
            N(0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA");
            S8(0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA");
            B8(0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA");
            B8(0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
            B8(0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
            N(0xC00B, "TLS_ECDH_RSA_WITH_NULL_SHA");
            S8(0xC00C, "TLS_ECDH_RSA_WITH_RC4_128_SHA");
            B8(0xC00D, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA");
            B8(0xC00E, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA");
            B8(0xC00F, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA");
            N(0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA");
            S8(0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA");
            B8(0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");
            B8(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
            B8(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
            N(0xC015, "TLS_ECDH_anon_WITH_NULL_SHA");
            S8(0xC016, "TLS_ECDH_anon_WITH_RC4_128_SHA");
            B8(0xC017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA");
            B8(0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA");
            B8(0xC019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA");
            B8(0xC01A, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA");
            B8(0xC01B, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA");
            B8(0xC01C, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA");
            B8(0xC01D, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA");
            B8(0xC01E, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA");
            B8(0xC01F, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA");
            B8(0xC020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA");
            B8(0xC021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA");
            B8(0xC022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA");
            B8(0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
            B8(0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
            B8(0xC025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256");
            B8(0xC026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384");
            B8(0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
            B8(0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
            B8(0xC029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256");
            B8(0xC02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384");
            S8(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
            S8(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
            S8(0xC02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
            S8(0xC02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384");
            S8(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
            S8(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
            S8(0xC031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256");
            S8(0xC032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384");
            S8(0xC033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA");
            B8(0xC034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA");
            B8(0xC035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA");
            B8(0xC036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA");
            B8(0xC037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256");
            B8(0xC038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384");
            N(0xC039, "TLS_ECDHE_PSK_WITH_NULL_SHA");
            N(0xC03A, "TLS_ECDHE_PSK_WITH_NULL_SHA256");
            N(0xC03B, "TLS_ECDHE_PSK_WITH_NULL_SHA384");
            B8(0xC03C, "TLS_RSA_WITH_ARIA_128_CBC_SHA256");
            B8(0xC03D, "TLS_RSA_WITH_ARIA_256_CBC_SHA384");
            B8(0xC03E, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256");
            B8(0xC03F, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384");
            B8(0xC040, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256");
            B8(0xC041, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384");
            B8(0xC042, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256");
            B8(0xC043, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384");
            B8(0xC044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256");
            B8(0xC045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384");
            B8(0xC046, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256");
            B8(0xC047, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384");
            B8(0xC048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256");
            B8(0xC049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384");
            B8(0xC04A, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256");
            B8(0xC04B, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384");
            B8(0xC04C, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256");
            B8(0xC04D, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384");
            B8(0xC04E, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256");
            B8(0xC04F, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384");
            S8(0xC050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256");
            S8(0xC051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384");
            S8(0xC052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256");
            S8(0xC053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384");
            S8(0xC054, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256");
            S8(0xC055, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384");
            S8(0xC056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256");
            S8(0xC057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384");
            S8(0xC058, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256");
            S8(0xC059, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384");
            S8(0xC05A, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256");
            S8(0xC05B, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384");
            S8(0xC05C, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256");
            S8(0xC05D, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384");
            S8(0xC05E, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256");
            S8(0xC05F, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384");
            S8(0xC060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256");
            S8(0xC061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384");
            S8(0xC062, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256");
            S8(0xC063, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384");
            B8(0xC064, "TLS_PSK_WITH_ARIA_128_CBC_SHA256");
            B8(0xC065, "TLS_PSK_WITH_ARIA_256_CBC_SHA384");
            B8(0xC066, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256");
            B8(0xC067, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384");
            B8(0xC068, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256");
            B8(0xC069, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384");
            S8(0xC06A, "TLS_PSK_WITH_ARIA_128_GCM_SHA256");
            S8(0xC06B, "TLS_PSK_WITH_ARIA_256_GCM_SHA384");
            S8(0xC06C, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256");
            S8(0xC06D, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384");
            S8(0xC06E, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256");
            S8(0xC06F, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384");
            B8(0xC070, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256");
            B8(0xC071, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384");
            B8(0xC072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256");
            B8(0xC073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384");
            B8(0xC074, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256");
            B8(0xC075, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384");
            B8(0xC076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256");
            B8(0xC077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384");
            B8(0xC078, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256");
            B8(0xC079, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384");
            S8(0xC07A, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256");
            S8(0xC07B, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384");
            S8(0xC07C, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256");
            S8(0xC07D, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384");
            S8(0xC07E, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256");
            S8(0xC07F, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384");
            S8(0xC080, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256");
            S8(0xC081, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384");
            S8(0xC082, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256");
            S8(0xC083, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384");
            S8(0xC084, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256");
            S8(0xC085, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384");
            S8(0xC086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256");
            S8(0xC087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384");
            S8(0xC088, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256");
            S8(0xC089, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384");
            S8(0xC08A, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256");
            S8(0xC08B, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384");
            S8(0xC08C, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256");
            S8(0xC08D, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384");
            S8(0xC08E, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256");
            S8(0xC08F, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384");
            S8(0xC090, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256");
            S8(0xC091, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384");
            S8(0xC092, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256");
            S8(0xC093, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384");
            B8(0xC094, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256");
            B8(0xC095, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384");
            B8(0xC096, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256");
            B8(0xC097, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384");
            B8(0xC098, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256");
            B8(0xC099, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384");
            B8(0xC09A, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256");
            B8(0xC09B, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384");
            S8(0xC09C, "TLS_RSA_WITH_AES_128_CCM");
            S8(0xC09D, "TLS_RSA_WITH_AES_256_CCM");
            S8(0xC09E, "TLS_DHE_RSA_WITH_AES_128_CCM");
            S8(0xC09F, "TLS_DHE_RSA_WITH_AES_256_CCM");
            S8(0xC0A0, "TLS_RSA_WITH_AES_128_CCM_8");
            S8(0xC0A1, "TLS_RSA_WITH_AES_256_CCM_8");
            S8(0xC0A2, "TLS_DHE_RSA_WITH_AES_128_CCM_8");
            S8(0xC0A3, "TLS_DHE_RSA_WITH_AES_256_CCM_8");
            S8(0xC0A4, "TLS_PSK_WITH_AES_128_CCM");
            S8(0xC0A5, "TLS_PSK_WITH_AES_256_CCM");
            S8(0xC0A6, "TLS_DHE_PSK_WITH_AES_128_CCM");
            S8(0xC0A7, "TLS_DHE_PSK_WITH_AES_256_CCM");
            S8(0xC0A8, "TLS_PSK_WITH_AES_128_CCM_8");
            S8(0xC0A9, "TLS_PSK_WITH_AES_256_CCM_8");
            S8(0xC0AA, "TLS_PSK_DHE_WITH_AES_128_CCM_8");
            S8(0xC0AB, "TLS_PSK_DHE_WITH_AES_256_CCM_8");

            DebugOutput("[+INFO] Cipher Suites Initialised");
        }
    }

    class CipherSuite
    {

        internal int suite;
        internal string name;
        internal bool isCBC;
        internal int strength;
    }

    class M
    {

        internal const int CHANGE_CIPHER_SPEC = 20;
        internal const int ALERT = 21;
        internal const int HANDSHAKE = 22;
        internal const int APPLICATION = 23;

        internal static void Enc16be(int val, byte[] buf, int off)
        {
            buf[off] = (byte)(val >> 8);
            buf[off + 1] = (byte)val;
        }

        internal static void Enc24be(int val, byte[] buf, int off)
        {
            buf[off] = (byte)(val >> 16);
            buf[off + 1] = (byte)(val >> 8);
            buf[off + 2] = (byte)val;
        }

        internal static void Enc32be(int val, byte[] buf, int off)
        {
            buf[off] = (byte)(val >> 24);
            buf[off + 1] = (byte)(val >> 16);
            buf[off + 2] = (byte)(val >> 8);
            buf[off + 3] = (byte)val;
        }

        internal static int Dec16be(byte[] buf, int off)
        {
            return ((int)buf[off] << 8)
                | (int)buf[off + 1];
        }

        internal static int Dec24be(byte[] buf, int off)
        {
            return ((int)buf[off] << 16)
                | ((int)buf[off + 1] << 8)
                | (int)buf[off + 2];
        }

        internal static uint Dec32be(byte[] buf, int off)
        {
            return ((uint)buf[off] << 24)
                | ((uint)buf[off + 1] << 16)
                | ((uint)buf[off + 2] << 8)
                | (uint)buf[off + 3];
        }

        internal static void ReadFully(Stream s, byte[] buf)
        {
            ReadFully(s, buf, 0, buf.Length);
        }

        internal static void ReadFully(Stream s, byte[] buf, int off, int len)
        {
            while (len > 0)
            {
                int rlen = s.Read(buf, off, len);
                if (rlen <= 0)
                {
                    throw new EndOfStreamException();
                }
                off += rlen;
                len -= rlen;
            }
        }

        static readonly DateTime Jan1st1970 =
            new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        internal static long CurrentTimeMillis()
        {
            return (long)(DateTime.UtcNow - Jan1st1970).TotalMilliseconds;
        }

        /*
         * Compute the SHA-1 hash of some bytes, returning the hash
         * value in hexadecimal.
         */
        internal static string DoSHA1(byte[] buf)
        {
            return DoSHA1(buf, 0, buf.Length);
        }

        internal static string DoSHA1(byte[] buf, int off, int len)
        {
            byte[] hv = new SHA1Managed().ComputeHash(buf, off, len);
            StringBuilder sb = new StringBuilder();
            foreach (byte b in hv)
            {
                sb.AppendFormat("{0:x2}", b);
            }
            return sb.ToString();
        }

        /*
         * A constant SSLv2 CLIENT-HELLO message. Only one connection
         * is needed for SSLv2, since the server response will contain
         * _all_ the cipher suites that the server is willing to
         * support.
         *
         * Note: when (mis)interpreted as a SSLv3+ record, this message
         * apparently encodes some data of (invalid) 0x80 type, using
         * protocol version TLS 44.1, and record length of 2 bytes.
         * Thus, the receiving part will quickly conclude that it will
         * not support that, instead of stalling for more data from the
         * client.
         */
        internal static byte[] SSL2_CLIENT_HELLO = {
		0x80, 0x2E,              // header (record length)
		0x01,                    // message type (CLIENT HELLO)
		0x00, 0x02,              // version (0x0002)
		0x00, 0x15,              // cipher specs list length
		0x00, 0x00,              // session ID length
		0x00, 0x10,              // challenge length
		0x01, 0x00, 0x80,        // SSL_CK_RC4_128_WITH_MD5
		0x02, 0x00, 0x80,        // SSL_CK_RC4_128_EXPORT40_WITH_MD5
		0x03, 0x00, 0x80,        // SSL_CK_RC2_128_CBC_WITH_MD5
		0x04, 0x00, 0x80,        // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
		0x05, 0x00, 0x80,        // SSL_CK_IDEA_128_CBC_WITH_MD5
		0x06, 0x00, 0x40,        // SSL_CK_DES_64_CBC_WITH_MD5
		0x07, 0x00, 0xC0,        // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
		0x54, 0x54, 0x54, 0x54,  // challenge data (16 bytes)
		0x54, 0x54, 0x54, 0x54,
		0x54, 0x54, 0x54, 0x54,
		0x54, 0x54, 0x54, 0x54
	};
    }

    // CanRead, CanSeek, CanWrite, Flush, Length, Position, Seek, SetLength

    class SSLRecord : Stream
    {

        const int MAX_RECORD_LEN = 16384;

        Stream sub;
        byte[] outBuf = new byte[MAX_RECORD_LEN + 5];
        int outPtr;
        int outVersion;
        int outType;
        byte[] inBuf = new byte[MAX_RECORD_LEN + 5];
        int inPtr;
        int inEnd;
        int inVersion;
        int inType;
        int inExpectedType;

        internal SSLRecord(Stream sub)
        {
            this.sub = sub;
            outPtr = 5;
            inPtr = 0;
            inEnd = 0;
        }

        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return true; } }
        public override long Length
        {
            get { throw new NotSupportedException(); }
        }
        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        internal void SetOutType(int type)
        {
            this.outType = type;
        }

        internal void SetOutVersion(int version)
        {
            this.outVersion = version;
        }

        public override void Flush()
        {
            outBuf[0] = (byte)outType;
            M.Enc16be(outVersion, outBuf, 1);
            M.Enc16be(outPtr - 5, outBuf, 3);
            sub.Write(outBuf, 0, outPtr);
            sub.Flush();
            outPtr = 5;
        }

        public override void WriteByte(byte b)
        {
            outBuf[outPtr++] = b;
            if (outPtr == outBuf.Length)
            {
                Flush();
            }
        }

        public void Write(byte[] buf)
        {
            Write(buf, 0, buf.Length);
        }

        public override void Write(byte[] buf, int off, int len)
        {
            while (len > 0)
            {
                int clen = Math.Min(outBuf.Length - outPtr, len);
                Array.Copy(buf, off, outBuf, outPtr, clen);
                outPtr += clen;
                off += clen;
                len -= clen;
                if (outPtr == outBuf.Length)
                {
                    Flush();
                }
            }
        }

        internal void SetExpectedType(int expectedType)
        {
            this.inExpectedType = expectedType;
        }

        internal int GetInVersion()
        {
            return inVersion;
        }

        void Refill()
        {
            for (; ; )
            {
                M.ReadFully(sub, inBuf, 0, 5);
                inType = inBuf[0];
                inVersion = M.Dec16be(inBuf, 1);
                inEnd = M.Dec16be(inBuf, 3);
                M.ReadFully(sub, inBuf, 0, inEnd);
                inPtr = 0;
                if (inType != inExpectedType)
                {
                    if (inType == M.ALERT)
                    {
                        /*
                         * We just ignore alert
                         * messages.
                         */
                        continue;
                    }
                    throw new IOException(
                        "unexpected record type: "
                        + inType);
                }
                return;
            }
        }

        public override int ReadByte()
        {
            while (inPtr == inEnd)
            {
                Refill();
            }
            return inBuf[inPtr++];
        }

        public override int Read(byte[] buf, int off, int len)
        {
            while (inPtr == inEnd)
            {
                Refill();
            }
            int clen = Math.Min(inEnd - inPtr, len);
            Array.Copy(inBuf, inPtr, buf, off, clen);
            inPtr += clen;
            return clen;
        }
    }

    /*
     * This class decodes a ServerHello message from the server. The
     * fields we are interested in are stored in the
     * package-accessible fields.
     */
    class ServerHello
    {

        internal int recordVersion;
        internal int protoVersion;
        internal long serverTime;
        internal int cipherSuite;
        internal int compression;
        internal string serverCertName;
        internal string serverCertHash;

        internal ServerHello(SSLRecord rec)
        {
            rec.SetExpectedType(M.HANDSHAKE);

            /*
             * First, get the handshake message header (4 bytes).
             * First byte should be 2 ("ServerHello"), then
             * comes the message size (over 3 bytes).
             */
            byte[] buf = new byte[4];
            M.ReadFully(rec, buf);
            recordVersion = rec.GetInVersion();
            if (buf[0] != 2)
            {
                throw new IOException("unexpected handshake"
                    + " message type: " + buf[0]);
            }
            buf = new byte[M.Dec24be(buf, 1)];

            /*
             * Read the complete message in RAM.
             */
            M.ReadFully(rec, buf);
            int ptr = 0;

            /*
             * The protocol version which we will use.
             */
            if (ptr + 2 > buf.Length)
            {
                throw new IOException("invalid ServerHello");
            }
            protoVersion = M.Dec16be(buf, 0);
            ptr += 2;

            /*
             * The server random begins with the server's notion
             * of the current time.
             */
            if (ptr + 32 > buf.Length)
            {
                throw new IOException("invalid ServerHello");
            }
            serverTime = 1000L * (long)M.Dec32be(buf, ptr);
            ptr += 32;

            /*
             * We skip the session ID.
             */
            if (ptr + 1 > buf.Length)
            {
                throw new IOException("invalid ServerHello");
            }
            ptr += 1 + buf[ptr];

            /*
             * The cipher suite and compression follow.
             */
            if (ptr + 3 > buf.Length)
            {
                throw new IOException("invalid ServerHello");
            }
            cipherSuite = M.Dec16be(buf, ptr);
            compression = buf[ptr + 2];

            /*
             * The ServerHello could include some extensions
             * here, which we ignore.
             */

            /*
             * We now read a few extra messages, until we
             * reach the server's Certificate message, or
             * ServerHelloDone.
             */
            for (; ; )
            {
                buf = new byte[4];
                M.ReadFully(rec, buf);
                int mt = buf[0];
                buf = new byte[M.Dec24be(buf, 1)];
                M.ReadFully(rec, buf);
                switch (mt)
                {
                    case 11:
                        ProcessCertificate(buf);
                        return;
                    case 14:
                        // ServerHelloDone
                        return;
                }
            }
        }

        private void ProcessCertificate(byte[] buf)
        {
            if (buf.Length <= 6)
            {
                return;
            }
            int len1 = M.Dec24be(buf, 0);
            if (len1 != buf.Length - 3)
            {
                return;
            }
            int len2 = M.Dec24be(buf, 3);
            if (len2 > buf.Length - 6)
            {
                return;
            }
            byte[] ec = new byte[len2];
            Array.Copy(buf, 6, ec, 0, len2);

            try
            {
                X509Certificate2 xc = new X509Certificate2(ec);
                serverCertName = xc.SubjectName.Name;
            }
            catch (Exception)
            {
                // ignored
                return;
            }
            serverCertHash = M.DoSHA1(ec);
        }
    }

    /*
     * This class represents the response of a server which knows
     $ SSLv2. It includes the list of cipher suites and the
     * identification of the server certificate.
     */
    class ServerHelloSSLv2
    {

        internal int[] cipherSuites;
        internal string serverCertName;
        internal string serverCertHash;

        internal ServerHelloSSLv2(Stream ss)
        {
            // Record length
            byte[] buf = new byte[2];
            M.ReadFully(ss, buf);
            int len = M.Dec16be(buf, 0);
            if ((len & 0x8000) == 0)
            {
                throw new IOException("not a SSLv2 record");
            }
            len &= 0x7FFF;
            if (len < 11)
            {
                throw new IOException(
                    "not a SSLv2 server hello");
            }
            buf = new byte[11];
            M.ReadFully(ss, buf);
            if (buf[0] != 0x04)
            {
                throw new IOException(
                    "not a SSLv2 server hello");
            }
            int certLen = M.Dec16be(buf, 5);
            int csLen = M.Dec16be(buf, 7);
            int connIdLen = M.Dec16be(buf, 9);
            if (len != 11 + certLen + csLen + connIdLen)
            {
                throw new IOException(
                    "not a SSLv2 server hello");
            }
            if (csLen == 0 || csLen % 3 != 0)
            {
                throw new IOException(
                    "not a SSLv2 server hello");
            }
            byte[] cert = new byte[certLen];
            M.ReadFully(ss, cert);
            byte[] cs = new byte[csLen];
            M.ReadFully(ss, cs);
            byte[] connId = new byte[connIdLen];
            M.ReadFully(ss, connId);
            cipherSuites = new int[csLen / 3];
            for (int i = 0, j = 0; i < csLen; i += 3, j++)
            {
                cipherSuites[j] = M.Dec24be(cs, i);
            }
            try
            {
                X509Certificate2 xc = new X509Certificate2(cert);
                serverCertName = xc.SubjectName.Name;
            }
            catch (Exception)
            {
                // ignored
                return;
            }
            serverCertHash = M.DoSHA1(cert);
        }
    }

}