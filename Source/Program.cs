using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

/*
 * RiotWadTool - C# console tool for Riot Games .wad.client archives
 * Target: .NET Framework 4.x  (csproj: <TargetFrameworkVersion>v4.5</TargetFrameworkVersion>)
 * Supports WAD version 1, 2, 3
 * Commands: unpack, pack, list
 *
 * Usage:
 *   RiotWadTool.exe unpack <file.wad.client> [output_dir]
 *   RiotWadTool.exe list   <file.wad.client>
 *   RiotWadTool.exe pack   <input_dir> <output.wad.client>
 *
 * Optional: add ZstdNet.dll reference for Zstd (v3) decompression.
 */

namespace RiotWadTool
{
    // ────────────────────────────────────────────────────────
    //  Entry structs
    // ────────────────────────────────────────────────────────

    class WadEntryV1
    {
        public byte[] Checksum;         // 8 bytes
        public int    Offset;
        public int    SizeUncompressed;
        public int    Size;
        public int    Type;             // 0=raw, 1=GZip
    }

    class WadEntryV2
    {
        public byte[] Checksum;
        public int    Offset;
        public int    SizeUncompressed;
        public int    Size;
        public byte   Type;             // 0=raw, 1=GZip
        public byte   Unk0, Unk1, Unk2;
        public long   Sha256Partial;
    }

    class WadEntryV3
    {
        public byte[] Checksum;
        public int    Offset;
        public int    SizeUncompressed;
        public int    Size;
        public byte   Type;             // 0=raw, 3=Zstd
        public byte   Unk0, Unk1, Unk2;
        public long   Sha256Partial;
    }

    // ────────────────────────────────────────────────────────
    //  Compression type constants
    // ────────────────────────────────────────────────────────

    static class CompType
    {
        public const byte None = 0;
        public const byte GZip = 1;
        public const byte Zstd = 3;
    }

    // ────────────────────────────────────────────────────────
    //  Magic bytes → file extension detection
    // ────────────────────────────────────────────────────────

    static class MagicDetect
    {
        public static string Detect(byte[] h)
        {
            if (h.Length < 2) return ".bin";

            // 2-byte signatures
            if (h[0] == 0xFF && h[1] == 0xD8)                                        return ".jpg";
            if (h[0] == 0x50 && h[1] == 0x4B)                                        return ".zip";
            if (h[0] == 0x7B)                                                         return ".json";
            if (h[0] == 0x3C)                                                         return ".xml";

            if (h.Length < 4) return ".bin";

            byte a = h[0], b = h[1], c = h[2], d = h[3];

            if (a == 0x89 && b == 0x50 && c == 0x4E && d == 0x47)                    return ".png";
            if (a == 0x47 && b == 0x49 && c == 0x46)                                 return ".gif";
            if (a == 0x52 && b == 0x49 && c == 0x46 && d == 0x46)                    return ".webp";
            if (a == 0x44 && b == 0x44 && c == 0x53)                                 return ".dds";
            if (a == 0x1A && b == 0x45 && c == 0xDF && d == 0xA3)                    return ".webm";
            if (a == 0x00 && b == 0x01 && c == 0x00 && d == 0x00)                    return ".ttf";
            if (a == 0x4F && b == 0x54 && c == 0x54 && d == 0x4F)                    return ".otf";
            if (a == 0x4C && b == 0x75 && c == 0x61)                                 return ".luac";
            if (a == 0x1B && b == 0x4C && c == 0x4A)                                 return ".lz4";
            if (a == 0x28 && b == 0xB5 && c == 0x2F && d == 0xFD)                    return ".zst";
            if (a == 0x52 && b == 0x53 && c == 0x54)                                 return ".rst";
            if (a == 0x54 && b == 0x52 && c == 0x4E && d == 0x54)                    return ".trnt";
            if (a == 0x53 && b == 0x4B && c == 0x4E)                                 return ".skn";
            if (a == 0x72 && b == 0x33 && c == 0x64)                                 return ".mapgeo";
            if (a == 0x4E && b == 0x56 && c == 0x52)                                 return ".nvr";
            if (a == 0xEF && b == 0xBB && c == 0xBF)                                 return ".txt";
            return ".bin";
        }
    }

    // ────────────────────────────────────────────────────────
    //  xxHash64 — used to hash file paths for pack command
    // ────────────────────────────────────────────────────────

    static class XxHash64
    {
        const ulong PRIME1 = 11400714785074694791UL;
        const ulong PRIME2 = 14029467366897019727UL;
        const ulong PRIME3 =  1609587929392839161UL;
        const ulong PRIME4 =  9650029242287828579UL;
        const ulong PRIME5 =  2870177450012600261UL;

        public static ulong Hash(string text)
        {
            // Riot uses lowercase ASCII path with '/' separator
            return Hash(Encoding.ASCII.GetBytes(text.ToLowerInvariant().Replace('\\', '/')));
        }

        public static ulong Hash(byte[] data)
        {
            int    len = data.Length;
            int    pos = 0;
            ulong  h64;

            if (len >= 32)
            {
                ulong v1 = unchecked(PRIME1 + PRIME2);
                ulong v2 = PRIME2;
                ulong v3 = 0;
                ulong v4 = unchecked(0UL - PRIME1);

                do
                {
                    v1 = Round(v1, BitConverter.ToUInt64(data, pos)); pos += 8;
                    v2 = Round(v2, BitConverter.ToUInt64(data, pos)); pos += 8;
                    v3 = Round(v3, BitConverter.ToUInt64(data, pos)); pos += 8;
                    v4 = Round(v4, BitConverter.ToUInt64(data, pos)); pos += 8;
                } while (pos <= len - 32);

                h64 = RotL(v1, 1) + RotL(v2, 7) + RotL(v3, 12) + RotL(v4, 18);
                h64 = Merge(h64, v1);
                h64 = Merge(h64, v2);
                h64 = Merge(h64, v3);
                h64 = Merge(h64, v4);
            }
            else
            {
                h64 = PRIME5;
            }

            h64 += (ulong)len;

            while (pos <= len - 8) { h64 ^= Round(0, BitConverter.ToUInt64(data, pos)); pos += 8; h64 = RotL(h64, 27) * PRIME1 + PRIME4; }
            while (pos <= len - 4) { h64 ^= BitConverter.ToUInt32(data, pos) * PRIME1;  pos += 4; h64 = RotL(h64, 23) * PRIME2 + PRIME3; }
            while (pos <  len)     { h64 ^= data[pos++] * PRIME5;                                  h64 = RotL(h64, 11) * PRIME1; }

            h64 ^= h64 >> 33; h64 *= PRIME2;
            h64 ^= h64 >> 29; h64 *= PRIME3;
            h64 ^= h64 >> 32;
            return h64;
        }

        static ulong Round(ulong acc, ulong v) { return RotL(acc + v * PRIME2, 31) * PRIME1; }
        static ulong Merge(ulong h,   ulong v) { return (h ^ Round(0, v)) * PRIME1 + PRIME4; }
        static ulong RotL (ulong v, int r)     { return (v << r) | (v >> (64 - r)); }
    }

    // ────────────────────────────────────────────────────────
    //  Pack helper — data block + metadata
    // ────────────────────────────────────────────────────────

    class PackEntry
    {
        public string FilePath;
        public byte[] Checksum;
        public int    Offset;
        public int    Size;
        public int    SizeUncompressed;
        public byte   Type;
        public long   Sha256Partial;
        public byte[] Data;
    }

    // ────────────────────────────────────────────────────────
    //  Main program
    // ────────────────────────────────────────────────────────

    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            PrintBanner();

            if (args.Length == 0)
            {
                PrintHelp();
                return;
            }

            string cmd = args[0].ToLowerInvariant();
            try
            {
                switch (cmd)
                {
                    case "unpack": CmdUnpack(args); break;
                    case "list":   CmdList(args);   break;
                    case "pack":   CmdPack(args);   break;
                    default:
                        Console.WriteLine("[!] Unknown command: " + cmd);
                        PrintHelp();
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[ERROR] " + ex.Message);
                Console.ResetColor();
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }

        // ────────────────────────────────────────────────────────
        //  UNPACK
        // ────────────────────────────────────────────────────────

        static void CmdUnpack(string[] args)
        {
            if (args.Length < 2) { Console.WriteLine("Usage: unpack <file.wad.client> [output_dir]"); return; }

            string wadPath = args[1];
            if (!File.Exists(wadPath)) { Console.WriteLine("[!] File not found: " + wadPath); return; }

            string outDir = args.Length >= 3
                ? args[2]
                : Path.Combine(Path.GetDirectoryName(wadPath), Path.GetFileNameWithoutExtension(wadPath));

            Directory.CreateDirectory(outDir);

            using (BinaryReader br = new BinaryReader(File.OpenRead(wadPath)))
            {
                byte major, minor;
                int  count;
                ReadHeader(br, out major, out minor, out count);

                Console.WriteLine(string.Format("[*] WAD v{0}.{1} — {2} entries → {3}", major, minor, count, outDir));

                int ok = 0, fail = 0;

                if (major == 1)
                {
                    List<WadEntryV1> entries = ReadEntriesV1(br, count);
                    foreach (WadEntryV1 e in entries)
                        ExtractEntry(br, HexName(e.Checksum), e.Offset, e.Size, e.SizeUncompressed, (byte)e.Type, outDir, ref ok, ref fail);
                }
                else if (major == 2)
                {
                    List<WadEntryV2> entries = ReadEntriesV2(br, count);
                    foreach (WadEntryV2 e in entries)
                        ExtractEntry(br, HexName(e.Checksum), e.Offset, e.Size, e.SizeUncompressed, e.Type, outDir, ref ok, ref fail);
                }
                else if (major == 3)
                {
                    List<WadEntryV3> entries = ReadEntriesV3(br, count);
                    foreach (WadEntryV3 e in entries)
                        ExtractEntry(br, HexName(e.Checksum), e.Offset, e.Size, e.SizeUncompressed, e.Type, outDir, ref ok, ref fail);
                }
                else
                {
                    Console.WriteLine("[!] Unsupported WAD version: " + major);
                    return;
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(string.Format("\n[OK] Done — {0} extracted, {1} failed.", ok, fail));
                Console.ResetColor();
            }
        }

        // ────────────────────────────────────────────────────────
        //  LIST
        // ────────────────────────────────────────────────────────

        static void CmdList(string[] args)
        {
            if (args.Length < 2) { Console.WriteLine("Usage: list <file.wad.client>"); return; }

            string wadPath = args[1];
            if (!File.Exists(wadPath)) { Console.WriteLine("[!] File not found: " + wadPath); return; }

            using (BinaryReader br = new BinaryReader(File.OpenRead(wadPath)))
            {
                byte major, minor;
                int  count;
                ReadHeader(br, out major, out minor, out count);

                Console.WriteLine(string.Format("WAD v{0}.{1} — {2} entries", major, minor, count));
                Console.WriteLine(new string('-', 80));
                Console.WriteLine(string.Format("{0,-6} {1,-18} {2,-12} {3,-12} {4,-12} {5,-6}",
                    "#", "Hash", "Offset", "CompSize", "RawSize", "Type"));
                Console.WriteLine(new string('-', 80));

                if (major == 1)
                {
                    List<WadEntryV1> entries = ReadEntriesV1(br, count);
                    for (int i = 0; i < entries.Count; i++)
                    {
                        WadEntryV1 e = entries[i];
                        Console.WriteLine(string.Format("{0,-6} {1,-18} {2,-12} {3,-12} {4,-12} {5,-6}",
                            i + 1, HexName(e.Checksum), e.Offset, e.Size, e.SizeUncompressed, TypeName((byte)e.Type)));
                    }
                }
                else if (major == 2)
                {
                    List<WadEntryV2> entries = ReadEntriesV2(br, count);
                    for (int i = 0; i < entries.Count; i++)
                    {
                        WadEntryV2 e = entries[i];
                        Console.WriteLine(string.Format("{0,-6} {1,-18} {2,-12} {3,-12} {4,-12} {5,-6}",
                            i + 1, HexName(e.Checksum), e.Offset, e.Size, e.SizeUncompressed, TypeName(e.Type)));
                    }
                }
                else if (major == 3)
                {
                    List<WadEntryV3> entries = ReadEntriesV3(br, count);
                    for (int i = 0; i < entries.Count; i++)
                    {
                        WadEntryV3 e = entries[i];
                        Console.WriteLine(string.Format("{0,-6} {1,-18} {2,-12} {3,-12} {4,-12} {5,-6}",
                            i + 1, HexName(e.Checksum), e.Offset, e.Size, e.SizeUncompressed, TypeName(e.Type)));
                    }
                }
                else
                {
                    Console.WriteLine("[!] Unsupported version: " + major);
                }

                Console.WriteLine(new string('-', 80));
            }
        }

        // ────────────────────────────────────────────────────────
        //  PACK  — hỗ trợ -v1, -v2, -v3 (mặc định v3)
        //
        //  Usage:
        //    pack <input_dir> <output.wad.client> [-v1|-v2|-v3]
        //
        //  Header sizes:
        //    v1: "RW"(2)+major(1)+minor(1)+entryHdrOff(2)+cellSz(2)+count(4) = 12
        //        entry: checksum(8)+offset(4)+sizeUncomp(4)+size(4)+type(4)  = 24
        //
        //    v2: "RW"(2)+major(1)+minor(1)+ecLen(1)+EC(83)+checksum(8)+
        //        entryHdrOff(2)+cellSz(2)+count(4)                           = 104
        //        entry: checksum(8)+offset(4)+sizeUncomp(4)+size(4)+
        //               type(1)+unk(3)+sha256(8)                             = 32
        //
        //    v3: "RW"(2)+major(1)+minor(1)+ECDSA(256)+checksum(8)+count(4)  = 272
        //        entry: checksum(8)+offset(4)+sizeUncomp(4)+size(4)+
        //               type(1)+unk(3)+sha256(8)                             = 32
        // ────────────────────────────────────────────────────────

        static void CmdPack(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: pack <input_dir> <output.wad.client> [-v1|-v2|-v3]");
                return;
            }

            string inDir   = args[1];
            string outFile = args[2];

            // Đọc tham số version (mặc định v3) và level nén (mặc định 9)
            byte targetVersion  = 3;
            int  zstdLevel      = 9;    // 1=nhanh, 9=tốt, 19=ultra (Riot dùng ~6-9)
            for (int i = 3; i < args.Length; i++)
            {
                string a = args[i].ToLowerInvariant();
                if (a == "-v1") { targetVersion = 1; continue; }
                if (a == "-v2") { targetVersion = 2; continue; }
                if (a == "-v3") { targetVersion = 3; continue; }
                if (a.StartsWith("-level:"))
                {
                    int parsed;
                    if (int.TryParse(a.Substring(7), out parsed) && parsed >= 1 && parsed <= 22)
                        zstdLevel = parsed;
                    else
                        Console.WriteLine("[!] -level: phai tu 1-22, dung mac dinh " + zstdLevel);
                    continue;
                }
            }

            if (!Directory.Exists(inDir))
            {
                Console.WriteLine("[!] Input directory not found: " + inDir);
                return;
            }

            string[] files = Directory.GetFiles(inDir, "*.*", SearchOption.AllDirectories);
            if (files.Length == 0)
            {
                Console.WriteLine("[!] No files found in input directory.");
                return;
            }

            Console.WriteLine(string.Format("[*] Packing {0} files → {1}  (WAD v{2}, Zstd level={3})",
                files.Length, outFile, targetVersion, zstdLevel));

            // ── Tính kích thước header theo version ──
            int entrySize;
            int headerSize;

            if (targetVersion == 1)
            {
                entrySize  = 24;    // checksum(8)+offset(4)+sizeUncomp(4)+size(4)+type(4)
                headerSize = 12 + files.Length * entrySize;
                //  "RW"(2)+major(1)+minor(1)+entryHdrOff(2)+cellSz(2)+count(4) = 12
            }
            else if (targetVersion == 2)
            {
                entrySize  = 32;    // checksum(8)+offset(4)+sizeUncomp(4)+size(4)+type(1)+unk(3)+sha256(8)
                headerSize = 104 + files.Length * entrySize;
                //  "RW"(2)+major(1)+minor(1)+ecLen(1)+EC(83)+checksum(8)+entryHdrOff(2)+cellSz(2)+count(4) = 104
            }
            else // v3
            {
                entrySize  = 32;
                headerSize = 272 + files.Length * entrySize;
                //  "RW"(2)+major(1)+minor(1)+ECDSA(256)+checksum(8)+count(4) = 272
            }

            // ── Thu thập dữ liệu từng file ──
            List<PackEntry> packEntries = new List<PackEntry>();
            int currentOffset = headerSize;

            foreach (string filePath in files)
            {
                string rel = filePath;
                if (rel.StartsWith(inDir))
                    rel = rel.Substring(inDir.Length).TrimStart('\\', '/');
                rel = rel.Replace('\\', '/');

                ulong  hash     = XxHash64.Hash(rel);
                byte[] checksum = BitConverter.GetBytes(hash);  // 8 bytes LE

                byte[] rawData      = File.ReadAllBytes(filePath);
                byte[] sha256Full   = SHA256.Create().ComputeHash(rawData);
                long   sha256Part   = BitConverter.ToInt64(sha256Full, 0);

                // ── Nén dữ liệu theo version ──
                byte[] storeData;
                byte   compType;

                if (targetVersion == 1)
                {
                    // v1: GZip (type=1) hoặc Raw (type=0)
                    byte[] gzData = CompressGZip(rawData);
                    if (gzData != null && gzData.Length < rawData.Length)
                    { storeData = gzData; compType = CompType.GZip; }
                    else
                    { storeData = rawData; compType = CompType.None; }
                }
                else if (targetVersion == 2)
                {
                    // v2: GZip (type=1) hoặc Raw (type=0)
                    byte[] gzData2 = CompressGZip(rawData);
                    if (gzData2 != null && gzData2.Length < rawData.Length)
                    { storeData = gzData2; compType = CompType.GZip; }
                    else
                    { storeData = rawData; compType = CompType.None; }
                }
                else
                {
                    // v3: Zstd (type=3) nếu có ZstdNet, fallback GZip, fallback Raw
                    byte[] zstdData = CompressZstd(rawData, zstdLevel);
                    if (zstdData != null && zstdData.Length < rawData.Length)
                    { storeData = zstdData; compType = CompType.Zstd; }
                    else
                    {
                        byte[] gzData3 = CompressGZip(rawData);
                        if (gzData3 != null && gzData3.Length < rawData.Length)
                        { storeData = gzData3; compType = CompType.GZip; }
                        else
                        { storeData = rawData; compType = CompType.None; }
                    }
                }

                PackEntry pe = new PackEntry();
                pe.FilePath         = filePath;
                pe.Checksum         = checksum;
                pe.SizeUncompressed = rawData.Length;
                pe.Type             = compType;
                pe.Data             = storeData;
                pe.Size             = storeData.Length;
                pe.Sha256Partial    = sha256Part;
                pe.Offset           = currentOffset;

                packEntries.Add(pe);
                currentOffset += pe.Size;
            }

            // ── Sắp xếp theo checksum tăng dần (chuẩn Riot) ──
            packEntries.Sort(delegate(PackEntry a, PackEntry b)
            {
                ulong ha = BitConverter.ToUInt64(a.Checksum, 0);
                ulong hb = BitConverter.ToUInt64(b.Checksum, 0);
                return ha.CompareTo(hb);
            });

            // Tính lại offset sau khi sort
            int off = headerSize;
            foreach (PackEntry pe in packEntries)
            {
                pe.Offset = off;
                off += pe.Size;
            }

            // ── Ghi file ──
            using (BinaryWriter bw = new BinaryWriter(File.Create(outFile)))
            {
                bw.Write((byte)'R');
                bw.Write((byte)'W');
                bw.Write(targetVersion);    // major
                bw.Write((byte)0);          // minor

                if (targetVersion == 1)
                {
                    // entryHeaderOffset (2), entryHeaderCellSize (2), count (4)
                    bw.Write((short)12);                    // entryHeaderOffset: ngay sau header
                    bw.Write((short)entrySize);             // cellSize
                    bw.Write(packEntries.Count);

                    foreach (PackEntry pe in packEntries)
                    {
                        bw.Write(pe.Checksum);              // 8
                        bw.Write(pe.Offset);                // 4
                        bw.Write(pe.SizeUncompressed);      // 4
                        bw.Write(pe.Size);                  // 4
                        bw.Write((int)pe.Type);             // 4  ← v1 dùng Int32 cho type
                    }
                }
                else if (targetVersion == 2)
                {
                    // ecLen (1) + EC (83) + filesChecksum (8) + entryHdrOff (2) + cellSz (2) + count (4)
                    bw.Write((byte)0);                      // ecLen = 0 (không có chữ ký)
                    bw.Write(new byte[83]);                 // EC bytes placeholder
                    bw.Write((long)0);                      // filesChecksum placeholder
                    bw.Write((short)104);                   // entryHeaderOffset
                    bw.Write((short)entrySize);             // cellSize
                    bw.Write(packEntries.Count);

                    foreach (PackEntry pe in packEntries)
                    {
                        bw.Write(pe.Checksum);              // 8
                        bw.Write(pe.Offset);                // 4
                        bw.Write(pe.SizeUncompressed);      // 4
                        bw.Write(pe.Size);                  // 4
                        bw.Write(pe.Type);                  // 1
                        bw.Write((byte)0);                  // unk x3
                        bw.Write((byte)0);
                        bw.Write((byte)0);
                        bw.Write(pe.Sha256Partial);         // 8
                    }
                }
                else // v3
                {
                    // ECDSA (256) + filesChecksum (8) + count (4)
                    bw.Write(new byte[256]);                // ECDSA placeholder
                    bw.Write((long)0);                      // filesChecksum placeholder
                    bw.Write(packEntries.Count);

                    foreach (PackEntry pe in packEntries)
                    {
                        bw.Write(pe.Checksum);              // 8
                        bw.Write(pe.Offset);                // 4
                        bw.Write(pe.SizeUncompressed);      // 4
                        bw.Write(pe.Size);                  // 4
                        bw.Write(pe.Type);                  // 1
                        bw.Write((byte)0);                  // unk x3
                        bw.Write((byte)0);
                        bw.Write((byte)0);
                        bw.Write(pe.Sha256Partial);         // 8
                    }
                }

                // Data blocks (giống nhau cho cả 3 version)
                foreach (PackEntry pe in packEntries)
                    bw.Write(pe.Data);
            }

            long outSize = new FileInfo(outFile).Length;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(string.Format("[OK] Packed {0} files  (WAD v{1}) — {2:N0} bytes",
                packEntries.Count, targetVersion, outSize));
            Console.ResetColor();
        }

        // ────────────────────────────────────────────────────────
        //  Header reader
        // ────────────────────────────────────────────────────────

        static void ReadHeader(BinaryReader br, out byte major, out byte minor, out int count)
        {
            char c1 = (char)br.ReadByte();
            char c2 = (char)br.ReadByte();
            if (c1 != 'R' || c2 != 'W')
                throw new InvalidDataException(string.Format("Invalid WAD signature: '{0}{1}' (expected 'RW')", c1, c2));

            major = br.ReadByte();
            minor = br.ReadByte();

            if (major == 1)
            {
                br.ReadInt16();     // entryHeaderOffset
                br.ReadInt16();     // entryHeaderCellSize
                count = br.ReadInt32();
            }
            else if (major == 2)
            {
                byte ecLen = br.ReadByte();
                br.ReadBytes(ecLen);
                br.ReadBytes(83 - ecLen);   // ECDSA padding
                br.ReadInt64();             // filesChecksum
                br.ReadInt16();             // entryHeaderOffset
                br.ReadInt16();             // entryHeaderCellSize
                count = br.ReadInt32();
            }
            else if (major == 3)
            {
                br.ReadBytes(256);  // ECDSA
                br.ReadInt64();     // filesChecksum
                count = br.ReadInt32();
            }
            else
            {
                throw new NotSupportedException("WAD version " + major + " is not supported.");
            }
        }

        // ────────────────────────────────────────────────────────
        //  Entry readers
        // ────────────────────────────────────────────────────────

        static List<WadEntryV1> ReadEntriesV1(BinaryReader br, int count)
        {
            List<WadEntryV1> list = new List<WadEntryV1>(count);
            for (int i = 0; i < count; i++)
            {
                WadEntryV1 e = new WadEntryV1();
                e.Checksum         = br.ReadBytes(8);
                e.Offset           = br.ReadInt32();
                e.SizeUncompressed = br.ReadInt32();
                e.Size             = br.ReadInt32();
                e.Type             = br.ReadInt32();
                list.Add(e);
            }
            return list;
        }

        static List<WadEntryV2> ReadEntriesV2(BinaryReader br, int count)
        {
            List<WadEntryV2> list = new List<WadEntryV2>(count);
            for (int i = 0; i < count; i++)
            {
                WadEntryV2 e = new WadEntryV2();
                e.Checksum         = br.ReadBytes(8);
                e.Offset           = br.ReadInt32();
                e.SizeUncompressed = br.ReadInt32();
                e.Size             = br.ReadInt32();
                e.Type             = br.ReadByte();
                e.Unk0             = br.ReadByte();
                e.Unk1             = br.ReadByte();
                e.Unk2             = br.ReadByte();
                e.Sha256Partial    = br.ReadInt64();
                list.Add(e);
            }
            return list;
        }

        static List<WadEntryV3> ReadEntriesV3(BinaryReader br, int count)
        {
            List<WadEntryV3> list = new List<WadEntryV3>(count);
            for (int i = 0; i < count; i++)
            {
                WadEntryV3 e = new WadEntryV3();
                e.Checksum         = br.ReadBytes(8);
                e.Offset           = br.ReadInt32();
                e.SizeUncompressed = br.ReadInt32();
                e.Size             = br.ReadInt32();
                e.Type             = br.ReadByte();
                e.Unk0             = br.ReadByte();
                e.Unk1             = br.ReadByte();
                e.Unk2             = br.ReadByte();
                e.Sha256Partial    = br.ReadInt64();
                list.Add(e);
            }
            return list;
        }

        // ────────────────────────────────────────────────────────
        //  Extract one entry to disk
        // ────────────────────────────────────────────────────────

        static void ExtractEntry(BinaryReader br, string baseName,
                                  int offset, int size, int sizeUncomp,
                                  byte type, string outDir,
                                  ref int ok, ref int fail)
        {
            try
            {
                br.BaseStream.Position = offset;
                byte[] raw = br.ReadBytes(size);

                byte[] data;

                if (type == CompType.None)
                {
                    data = raw;
                }
                else if (type == CompType.GZip)
                {
                    using (MemoryStream ms = new MemoryStream(raw))
                    using (GZipStream gz = new GZipStream(ms, CompressionMode.Decompress))
                    using (MemoryStream outMs = new MemoryStream())
                    {
                        gz.CopyTo(outMs);
                        data = outMs.ToArray();
                    }
                }
                else if (type == CompType.Zstd)
                {
                    data = DecompressZstd(raw);
                }
                else
                {
                    Console.WriteLine(string.Format("  [?] Unknown type {0} for {1} — saving raw", type, baseName));
                    data = raw;
                }

                string ext     = data.Length >= 4 ? MagicDetect.Detect(data) : ".bin";
                string outPath = Path.Combine(outDir, baseName + ext);

                File.WriteAllBytes(outPath, data);
                Console.WriteLine(string.Format("  [+] {0}{1}  ({2:N0} bytes, type={3})", baseName, ext, data.Length, type));
                ok++;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(string.Format("  [!] {0} — {1}", baseName, ex.Message));
                Console.ResetColor();
                fail++;
            }
        }

        // ────────────────────────────────────────────────────────
        //  Zstd decompression — requires ZstdNet.dll reference
        //  Project → Add Reference → Browse → ZstdNet.dll
        // ────────────────────────────────────────────────────────

        static byte[] DecompressZstd(byte[] compressed)
        {
            // Try to use ZstdNet via reflection (no hard compile dependency)
            Type decompType = Type.GetType("ZstdNet.Decompressor, ZstdNet");
            if (decompType != null)
            {
                using (IDisposable dec = (IDisposable)Activator.CreateInstance(decompType))
                {
                    System.Reflection.MethodInfo unwrap = decompType.GetMethod("Unwrap", new Type[] { typeof(byte[]) });
                    if (unwrap != null)
                        return (byte[])unwrap.Invoke(dec, new object[] { compressed });
                }
            }

            // Alternatively try DecompressionStream (ZstdNet 1.4+)
            Type streamType = Type.GetType("ZstdNet.DecompressionStream, ZstdNet");
            if (streamType != null)
            {
                using (MemoryStream inMs = new MemoryStream(compressed))
                using (Stream zs = (Stream)Activator.CreateInstance(streamType, new object[] { inMs }))
                using (MemoryStream outMs = new MemoryStream())
                {
                    zs.CopyTo(outMs);
                    return outMs.ToArray();
                }
            }

            throw new NotSupportedException(
                "Zstd decompression requires ZstdNet.dll.\n" +
                "  1. Copy ZstdNet.dll + libzstd.dll (x64/x86) beside the exe\n" +
                "  2. In Visual Studio: Project → Add Reference → Browse → ZstdNet.dll");
        }

        // ────────────────────────────────────────────────────────
        //  GZip compression helper
        //  Trả về null nếu lỗi
        // ────────────────────────────────────────────────────────

        static byte[] CompressGZip(byte[] data)
        {
            try
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    using (GZipStream gz = new GZipStream(ms, CompressionLevel.Optimal, true))
                        gz.Write(data, 0, data.Length);
                    return ms.ToArray();
                }
            }
            catch
            {
                return null;
            }
        }

        // ────────────────────────────────────────────────────────
        //  Zstd compression helper — dùng ZstdNet nếu có
        //  Trả về null nếu không có ZstdNet hoặc lỗi
        // ────────────────────────────────────────────────────────

        // level: 1=fastest, 9=best, 19=ultra, 22=ultra+dict
        // Riot thường dùng level 6-9; mặc định 9 để sát file gốc nhất
        static byte[] CompressZstd(byte[] data, int level = 9)
        {
            try
            {
                // ── ZstdNet.Compressor(CompressionOptions) — ZstdNet <= 1.3.x ──
                // CompressionOptions nhận int level trong constructor
                Type optType  = Type.GetType("ZstdNet.CompressionOptions, ZstdNet");
                Type compType = Type.GetType("ZstdNet.Compressor, ZstdNet");
                if (optType != null && compType != null)
                {
                    // new CompressionOptions(level)
                    object opt = Activator.CreateInstance(optType, new object[] { level });
                    using (IDisposable comp = (IDisposable)Activator.CreateInstance(compType, new object[] { opt }))
                    {
                        System.Reflection.MethodInfo wrap = compType.GetMethod("Wrap", new Type[] { typeof(byte[]) });
                        if (wrap != null)
                            return (byte[])wrap.Invoke(comp, new object[] { data });
                    }
                }

                // Fallback: Compressor() không có options (dùng level mặc định)
                if (compType != null)
                {
                    using (IDisposable comp = (IDisposable)Activator.CreateInstance(compType))
                    {
                        System.Reflection.MethodInfo wrap = compType.GetMethod("Wrap", new Type[] { typeof(byte[]) });
                        if (wrap != null)
                            return (byte[])wrap.Invoke(comp, new object[] { data });
                    }
                }

                // ── ZstdNet.CompressionStream — ZstdNet 1.4+ ──
                Type streamType = Type.GetType("ZstdNet.CompressionStream, ZstdNet");
                if (streamType != null)
                {
                    // Thử constructor (Stream, CompressionOptions)
                    if (optType != null)
                    {
                        object opt2 = Activator.CreateInstance(optType, new object[] { level });
                        using (MemoryStream ms = new MemoryStream())
                        {
                            using (Stream zs = (Stream)Activator.CreateInstance(
                                streamType, new object[] { ms, opt2 }))
                                zs.Write(data, 0, data.Length);
                            return ms.ToArray();
                        }
                    }
                    // Thử constructor (Stream) — không truyền level
                    using (MemoryStream ms2 = new MemoryStream())
                    {
                        using (Stream zs2 = (Stream)Activator.CreateInstance(streamType, new object[] { ms2 }))
                            zs2.Write(data, 0, data.Length);
                        return ms2.ToArray();
                    }
                }

                // ZstdNet không có → null, caller fallback GZip/Raw
                return null;
            }
            catch
            {
                return null;
            }
        }

        // ────────────────────────────────────────────────────────
        //  Utilities
        // ────────────────────────────────────────────────────────

        static string HexName(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                sb.Append(b.ToString("X2"));
            return sb.ToString();
        }

        static string TypeName(byte t)
        {
            switch (t)
            {
                case 0: return "Raw";
                case 1: return "GZip";
                case 3: return "Zstd";
                default: return "#" + t;
            }
        }

        static void PrintBanner()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("+------------------------------------------+");
            Console.WriteLine("|  RiotWadTool  -  WAD v1 / v2 / v3        |");
            Console.WriteLine("|  .NET Framework 4.x  |  pack/unpack/list  |");
            Console.WriteLine("+------------------------------------------+");
            Console.ResetColor();
        }

        static void PrintHelp()
        {
            Console.WriteLine();
            Console.WriteLine("  Usage:");
            Console.WriteLine("    RiotWadTool.exe unpack <file.wad.client> [output_dir]");
            Console.WriteLine("    RiotWadTool.exe list   <file.wad.client>");
            Console.WriteLine("    RiotWadTool.exe pack   <input_dir> <output.wad.client> [-v1|-v2|-v3] [-level:N]");
            Console.WriteLine();
            Console.WriteLine("  Examples:");
            Console.WriteLine("    RiotWadTool.exe unpack Scripts.wad.client");
            Console.WriteLine("    RiotWadTool.exe unpack Scripts.wad.client C:\\output");
            Console.WriteLine("    RiotWadTool.exe list   Scripts.wad.client");
            Console.WriteLine("    RiotWadTool.exe pack   C:\\mods\\Scripts out.wad.client              <- v3, level 9");
            Console.WriteLine("    RiotWadTool.exe pack   C:\\mods\\Scripts out.wad.client -level:6   <- v3, level 6");
            Console.WriteLine("    RiotWadTool.exe pack   C:\\mods\\Scripts out.wad.client -v1");
            Console.WriteLine("    RiotWadTool.exe pack   C:\\mods\\Scripts out.wad.client -v2");
            Console.WriteLine("    RiotWadTool.exe pack   C:\\mods\\Scripts out.wad.client -v3");
            Console.WriteLine();
            Console.WriteLine("  Pack - cau truc header theo version:");
            Console.WriteLine("    v1: RW+major+minor+entryHdrOff(2)+cellSz(2)+count(4)  / entry 24 bytes");
            Console.WriteLine("    v2: RW+major+minor+EC(84)+checksum(8)+hdrOff+cellSz+count / entry 32 bytes");
            Console.WriteLine("    v3: RW+major+minor+ECDSA(256)+checksum(8)+count(4)    / entry 32 bytes");
            Console.WriteLine();
            Console.WriteLine("  Zstd level (chi ap dung v3):");
            Console.WriteLine("    1-3  : nhanh, nen it (de test)");
            Console.WriteLine("    6-9  : can bang - Riot thuong dung vung nay (mac dinh 9)");
            Console.WriteLine("    10-19: nen rat tot, cham hon");
            Console.WriteLine("    20-22: ultra (rat cham, hiem khi can)");
            Console.WriteLine();
            Console.WriteLine("  Notes:");
            Console.WriteLine("    - Ten file = xxHash64(duong dan noi bo) + extension tu magic bytes.");
            Console.WriteLine("    - WAD v3 Zstd: them ZstdNet.dll reference de giai nen.");
        }
    }
}
