using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Digests;

namespace AliSign
{
    public partial class Form1 : Form
    {
        public const int HASH_SIZE = 20;
        public const int SIGNATURE_SIZE = 40;
        public const int RETRY_SIGN = 10;
        // TODO: confirm the size of the DSA private key
        public const int PRIVATE_KEY_SIZE = 684;
        public const int PRIVATE_KEY_SIZE_2 = 672;
        public const int PUBLIC_KEY_SIZE = 404;
        public const int SIZE_FILE_BIOS = 0x800000;

        public const int OFFSET_HASH_LIST_START = 0x37c;
        public const int OFFSET_HASH_LIST_END_PLUS1 = 0x10000;
        public const int OFFSET_UBC_PUBLIC_KEY = 0x3c;
        public const int OFFSET_BOOT_LOADER_PUBLIC_KEY = 0x1d0;
        public const int OFFSET_UBIOS_VERSION = 0x364;
        public const int OFFSET_UBIOS_PUBLIC_KEY = 0x7f8020;

        public const int MAX_HASH_PATH_COUNT = (OFFSET_HASH_LIST_END_PLUS1 - OFFSET_HASH_LIST_START) / HASH_SIZE;

        public const int SIZE_FILE_DISK = 0x100000;

        public const int SIZE_FILE_UBC = 0x8000;
        public const int OFFSET_HASH_LIST_START_UBC = 0x2000;
        public const int OFFSET_HASH_LIST_END_PLUS1_UBC = 0x4000;
        public const int OFFSET_UBIOS_VERSION_UBC = 0x7fa6;
        public const int OFFSET_UBC_VERSION = 0x7fbe;

        // Common encripto variables
        IDigest hashFunction;
        IDsa signer;
        // for BIOS sign
        public byte[] bytesImageBios;
        public int identificationAlignment = 16;
        public bool is1stTime = true;
        // for Disk sign
        public byte[] bytesImageDisk;
        // for UBC sign
        public byte[] bytesImageUbc;

        public Form1()
        {
            InitializeComponent();
            restoreSettings();
        }

        //
        // TODO: it is not working to argument save/restore listboxitems yet
        //
        private void SaveListBoxToSettings(ListBox listBox, string settingName)
        {
            string listboxContents = Convert.ToBase64String(
                System.Text.Encoding.Unicode.GetBytes(
                    string.Join(Environment.NewLine, listBox.Items.Cast<string>())
                )
            );

            // Save the string to the project settings
            Properties.Settings.Default[settingName] = listboxContents;
            //Properties.Settings.Default.Save();
        }

        private void RestoreListBoxFromSettings(ListBox listBox, string settingName)
        {
            // Get the base64 string from the project settings
            string listboxContents = (string)Properties.Settings.Default[settingName];

            // Convert the base64 string to a regular string
            string listboxContentsString = System.Text.Encoding.Unicode.GetString(
                Convert.FromBase64String(listboxContents)
            );

            // Split the string into an array of strings, one for each item in the listbox
            string[] items = listboxContentsString.Split(
                new[] { Environment.NewLine },
                StringSplitOptions.None
            );

            // Add the items to the listbox
            listBox.Items.AddRange(items);
        }

        private void restoreSettings()
        {
            this.Location = Properties.Settings.Default.F1Location;
            this.Size = Properties.Settings.Default.F1Size;

            RestoreListBoxFromSettings(listBoxHashUbios, "listBoxHashUbios");
            RestoreListBoxFromSettings(listBoxHashUbc, "listBoxHashUbc");

            textBoxWorkingFolder.Text = Properties.Settings.Default.textBoxWorkingFolder;
            textBoxDsaPrivateKey.Text = Properties.Settings.Default.textBoxDsaPrivateKey;

            textBoxSignedImageBios.Text = Properties.Settings.Default.textBoxSignedImageBios;
            textBoxUbiosVersion.Text = Properties.Settings.Default.textBoxUbiosVersion;
            textBoxUbiosPublicKey.Text = Properties.Settings.Default.textBoxUbiosPublicKey;
            textBoxUbcPublicKey.Text = Properties.Settings.Default.textBoxUbcPublicKey;
            textBoxBootLoaderPublicKey.Text = Properties.Settings.Default.textBoxBootLoaderPublicKey;
            // this filed must restore last to the tab page
            textBoxImageBios.Text = Properties.Settings.Default.textBoxImageBios;

            textBoxSignedImageDisk.Text = Properties.Settings.Default.textBoxSignedImageDisk;
            // this filed must restore last to the tab page
            textBoxImageDisk.Text = Properties.Settings.Default.textBoxImageDisk;

            textBoxSignedImageUbc.Text = Properties.Settings.Default.textBoxSignedImageUbc;
            textBoxUbiosVersionUbc.Text = Properties.Settings.Default.textBoxUbiosVersionUbc;
            textBoxUbcVersion.Text = Properties.Settings.Default.textBoxUbcVersion;
            // this filed must restore last to the tab page
            textBoxImageUbc.Text = Properties.Settings.Default.textBoxImageUbc;
        }

        private void saveSettings()
        {
            if (this.WindowState == FormWindowState.Normal)
            {
                // save location and size if the state is normal
                Properties.Settings.Default.F1Location = this.Location;
                Properties.Settings.Default.F1Size = this.Size;
            }
            else
            {
                // save the RestoreBounds if the form is minimized or maximized!
                Properties.Settings.Default.F1Location = this.RestoreBounds.Location;
                Properties.Settings.Default.F1Size = this.RestoreBounds.Size;
            }

            SaveListBoxToSettings(listBoxHashUbios, "listBoxHashUbios");
            SaveListBoxToSettings(listBoxHashUbc, "listBoxHashUbc");

            Properties.Settings.Default.textBoxWorkingFolder = textBoxWorkingFolder.Text;
            Properties.Settings.Default.textBoxDsaPrivateKey = textBoxDsaPrivateKey.Text;

            Properties.Settings.Default.textBoxImageBios = textBoxImageBios.Text;
            Properties.Settings.Default.textBoxSignedImageBios = textBoxSignedImageBios.Text;
            Properties.Settings.Default.textBoxUbiosVersion = textBoxUbiosVersion.Text;
            Properties.Settings.Default.textBoxUbiosPublicKey = textBoxUbiosPublicKey.Text;
            Properties.Settings.Default.textBoxUbcPublicKey = textBoxUbcPublicKey.Text;
            Properties.Settings.Default.textBoxBootLoaderPublicKey = textBoxBootLoaderPublicKey.Text;

            Properties.Settings.Default.textBoxImageDisk = textBoxImageDisk.Text;
            Properties.Settings.Default.textBoxSignedImageDisk = textBoxSignedImageDisk.Text;

            Properties.Settings.Default.textBoxImageUbc = textBoxImageUbc.Text;
            Properties.Settings.Default.textBoxSignedImageUbc = textBoxSignedImageUbc.Text;
            Properties.Settings.Default.textBoxUbiosVersionUbc = textBoxUbiosVersionUbc.Text;
            Properties.Settings.Default.textBoxUbcVersion = textBoxUbcVersion.Text;

            Properties.Settings.Default.Save();
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            saveSettings();
        }

        private string buttonFilePath_Click(string filePath)
        {
            if (this.openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                filePath = this.openFileDialog1.FileName;
            }
            return filePath;
        }

        private void buttonHashAdd_Click(object sender, EventArgs e)
        {
            if (listBoxHashUbios.Items.Count == 0)
            {
                var files = Directory.GetFiles(textBoxWorkingFolder.Text, "*.*", SearchOption.AllDirectories);

                foreach (string file in files)
                {
                    var info = new FileInfo(file);
                    if (info.Length == HASH_SIZE)
                    {
                        listBoxHashUbios.Items.Add(info.FullName);
                    }
                }
            }
            else
            {
                string hash_fp = "";
                hash_fp = buttonFilePath_Click(hash_fp);
                if (!String.IsNullOrEmpty(hash_fp))
                {
                    var info = new FileInfo(hash_fp);
                    if (info.Length == HASH_SIZE)
                    {
                        listBoxHashUbios.Items.Add(hash_fp);
                    }
                    else
                    {
                        MessageBox.Show("Hash file size is limited to 20 bytes");
                    }
                }
            }

        }

        public string currentWorkingFolder;

        private void buttonWorkingFolder_Click(object sender, EventArgs e)
        {
            if (Directory.Exists(textBoxWorkingFolder.Text))
            {
                folderBrowserDialog1.SelectedPath = textBoxWorkingFolder.Text;
            }
            if (folderBrowserDialog1.ShowDialog() == DialogResult.OK)
            {
                textBoxWorkingFolder.Text = folderBrowserDialog1.SelectedPath;
                resetInputFiles();
            }
        }
        
        private void textBoxWorkingFolder_Validating(object sender, CancelEventArgs e)
        {
            System.Windows.Forms.TextBox textBox = (System.Windows.Forms.TextBox)sender;
            string text = textBox.Text;

            // Check if the specified folder exists
            if (Directory.Exists(text))
            {
                resetInputFiles();
            }
        }

        private void resetInputFiles()
        {
            if (textBoxWorkingFolder.Text == currentWorkingFolder)
            {
                return;
            }
            currentWorkingFolder = textBoxWorkingFolder.Text;

            textBoxImageBios.Text = string.Empty;
            textBoxDsaPrivateKey.Text = string.Empty;
            textBoxUbcPublicKey.Text = string.Empty;
            textBoxBootLoaderPublicKey.Text = string.Empty;

            textBoxImageDisk.Text = string.Empty;

            textBoxImageUbc.Text = string.Empty;

            listBoxHashUbios.Items.Clear();

            var files = Directory.GetFiles(textBoxWorkingFolder.Text, "*.*", SearchOption.AllDirectories);

            foreach (string file in files)
            {
                var info = new FileInfo(file);
                //
                // skip files
                //
                if (info.Name.ToUpper().Contains("OUTPUT") || info.Name.ToUpper().Contains("SIGNED"))
                {
                    continue;
                }
                //
                // Guess input files
                //
                if (info.Length == HASH_SIZE)
                {
                    listBoxHashUbios.Items.Add(info.FullName);
                    continue;
                }
                // TODO: confirm the size of the private key
                if (info.Length == PRIVATE_KEY_SIZE || info.Length == PRIVATE_KEY_SIZE_2)
                {
                    textBoxDsaPrivateKey.Text = info.FullName;
                    continue;
                }
                if (info.Length == PUBLIC_KEY_SIZE)
                {
                    if (info.Name.ToUpper().Contains("UBC"))
                    {
                        textBoxUbcPublicKey.Text = info.FullName;
                        continue;
                    }
                    if (info.Name.ToUpper().Contains("UBIOS"))
                    {
                        textBoxUbiosPublicKey.Text = info.FullName;
                        continue;
                    }
                    if (info.Name.ToUpper().Contains("MBR"))
                    {
                        textBoxBootLoaderPublicKey.Text = info.FullName;
                        //continue;
                    }
                    continue;
                }
                if (info.Length == SIZE_FILE_BIOS)
                {
                    textBoxImageBios.Text = info.FullName;
                    continue;
                }
                if (info.Length == SIZE_FILE_DISK)
                {
                    textBoxImageDisk.Text = info.FullName;
                    continue;
                }
                if (info.Length == SIZE_FILE_UBC)
                {
                    textBoxImageUbc.Text = info.FullName;
                    continue;
                }
            }
            return;
        }

        private long searchBytes(byte[] needle)
        {
            if (bytesImageBios == null)
            {
                return -1;
            }
            var len = needle.Length;
            var limit = bytesImageBios.Length - len;
            for (var i = 0; i <= limit; i += identificationAlignment)
            {
                var k = 0;
                for (; k < len; k++)
                {
                    if (needle[k] != bytesImageBios[i + k]) break;
                }
                if (k == len) return i;
            }
            return -1;
        }

        private void enableControlsBios(bool isValid)
        {
            textBoxSignedImageBios.Enabled = isValid;
            buttonSignedImageBios.Enabled = isValid;
            textBoxUbiosVersion.Enabled = isValid;
            textBoxUbiosPublicKey.Enabled = isValid;
            buttonUbiosPublicKey.Enabled = isValid;
            textBoxUbcPublicKey.Enabled = isValid;
            buttonUbcPublicKey.Enabled = isValid;
            textBoxBootLoaderPublicKey.Enabled = isValid;
            buttonBootLoaderPublicKey.Enabled = isValid;
            buttonHashAdd.Enabled = isValid;
            buttonHashRemove.Enabled = isValid;
            listBoxHashUbios.Enabled = isValid;
            buttonSignBios.Enabled = isValid;
        }

        private bool isValidImageBios()
        {
            //
            // Validation ADLink identifications
            //
            byte[] AdlinkBiosIdentification1 = Encoding.ASCII.GetBytes("BIOS_MADE_BY_ADLINK");
            //byte[] AdlinkBiosIdentification1 = Encoding.ASCII.GetBytes("BIOS_MADE_BY_ADLINX");
            var AdlinkBiosIdentification2 = new byte[] { 0x0e, 0x0e, 0x15, 0x23, 0x3e, 0x25, 0x1e, 0x5f, 0x04, 0x58, 0x01, 0x44, 0x57, 0x18, 0x14, 0x61 };
            //var AdlinkBiosIdentification2 = new byte[] { 0x0e, 0x0e, 0x15, 0x23, 0x3e, 0x25, 0x1e, 0x5f, 0x04, 0x58, 0x01, 0x44, 0x57, 0x18, 0x14, 0x60 };
            if (searchBytes(AdlinkBiosIdentification1) == -1)
            {
                //MessageBox.Show("This ROM image is not supported 1.");
                return false;
            }
            if (searchBytes(AdlinkBiosIdentification2) == -1)
            {
                //MessageBox.Show("This ROM image is not supported 2.");
                return false;
            }
            //
            // Validate signature 90 90 E9
            //
            byte[] validSignature = new byte[] { 0x90, 0x90, 0xe9 };
            //byte[] validSignature = new byte[] { 0x90, 0x90, 0xe8 };
            var len = validSignature.Length;
            var validSignarueOffset = bytesImageBios.Length - 16;
            var i = 0;
            for (; i < len; i++)
            {
                if (validSignature[i] != bytesImageBios[i + validSignarueOffset]) break;
            }
            if (i < len)
            {
                //MessageBox.Show("Incorrect file format: ROM Image not ended with 90 90 E9 ....");
                return false;
            }

            return true;
        }

        private void enableControlsUbc(bool isValid)
        {
            textBoxSignedImageUbc.Enabled = isValid;
            buttonSignedImageUbc.Enabled = isValid;
            textBoxUbiosVersionUbc.Enabled = isValid;
            textBoxUbcVersion.Enabled = isValid;
            buttonHashAddUbc.Enabled = isValid;
            buttonHashRemoveUbc.Enabled = isValid;
            listBoxHashUbc.Enabled = isValid;
            buttonSignUbc.Enabled = isValid;
        }

        private void textBoxImageUbc_TextChanged(object sender, EventArgs e)
        {
            System.Windows.Forms.TextBox textBox = (System.Windows.Forms.TextBox)sender;
            string text = textBox.Text;

            if (!File.Exists(text))
            {
                enableControlsUbc(false);
                return;
            }
            //
            // Read Image file to bytes[] bytesImageUbc
            //
            bytesImageUbc = File.ReadAllBytes(text);
            if (bytesImageUbc.Length != SIZE_FILE_UBC)
            {
                enableControlsUbc(false);
                return;
            }
            //
            // default output file name
            //
            if (textBoxSignedImageUbc.Text.Length == 0)
            {
                textBoxSignedImageUbc.Text = Path.GetDirectoryName(text) + Path.DirectorySeparatorChar + Path.GetFileNameWithoutExtension(text) + "_signed" + Path.GetExtension(text); ;
            }
            //
            // retrieve version nubers from image
            //
            if (textBoxUbiosVersionUbc.Text.Length == 0)
            {
                byte[] bytesUbiosVersion = subByteArray(bytesImageUbc, OFFSET_UBIOS_VERSION_UBC, OFFSET_UBIOS_VERSION_UBC + textBoxUbiosVersionUbc.MaxLength);

                bool all0xff = true;
                foreach (byte b in bytesUbiosVersion)
                {
                    if (b != 0xff)
                    {
                        all0xff = false;
                        break;
                    }
                }

                if (all0xff)
                {
                    textBoxUbiosVersionUbc.Text = textBoxUbiosVersion.Text;
                }
                else
                {
                    textBoxUbiosVersionUbc.Text = System.Text.Encoding.UTF8.GetString(bytesUbiosVersion).Replace("\0", string.Empty);
                }
            }
            if (textBoxUbcVersion.Text.Length == 0)
            {
                textBoxUbcVersion.Text = System.Text.Encoding.UTF8.GetString(subByteArray(bytesImageUbc, OFFSET_UBC_VERSION, OFFSET_UBC_VERSION + textBoxUbcVersion.MaxLength)).Replace("\0", string.Empty);
            }

            enableControlsUbc(true);
        }

        private byte[] subByteArray(byte[] originalArray, int startIndex, int endIndex_1)
        {
            int length = endIndex_1 - startIndex;
            byte[] subsetArray = new byte[length];
            Array.Copy(originalArray, startIndex, subsetArray, 0, length);
            return subsetArray;
        }

        private void textBoxImageBios_TextChanged(object sender, EventArgs e)
        {
            System.Windows.Forms.TextBox textBox = (System.Windows.Forms.TextBox)sender;
            string text = textBox.Text;

            if (File.Exists(text))
            {
                //
                // Read Image file to bytes[] bytesImageBios
                //
                bytesImageBios = File.ReadAllBytes(text);
                //
                // support old project which size is 4MB and the identification is not 16 bytes aligned
                //
                //if (bytesImageBios.Length >= 0x800000)
                //{
                //    identificationAlignment = 16;
                //}
                //else
                //{
                //    identificationAlignment = 1;
                //}
                if (textBoxSignedImageBios.Text.Length == 0)
                {
                    textBoxSignedImageBios.Text = Path.GetDirectoryName(text) + Path.DirectorySeparatorChar + Path.GetFileNameWithoutExtension(text) + "_signed" + Path.GetExtension(text); ;
                }
                //
                // retrueve version nubers from image
                //
                if (textBoxUbiosVersion.Text.Length == 0)
                {
                    textBoxUbiosVersion.Text = System.Text.Encoding.UTF8.GetString(subByteArray(bytesImageBios, OFFSET_UBIOS_VERSION, (OFFSET_UBIOS_VERSION + textBoxUbiosVersion.MaxLength))).Replace("\0", string.Empty);
                }
                enableControlsBios(isValidImageBios());
            }
            else
            {
                enableControlsBios(false);
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            if (Properties.Settings.Default.F1Size.Width == 0 || Properties.Settings.Default.F1Size.Height == 0)
            {
                // first start
                // optional: add default values
            }
            else
            {
                //this.WindowState = Properties.Settings.Default.F1State;

                // we don't want a minimized window at startup
                if (this.WindowState == FormWindowState.Minimized) this.WindowState = FormWindowState.Normal;

                this.Location = Properties.Settings.Default.F1Location;
                this.Size = Properties.Settings.Default.F1Size;
            }
            // update title text
            string assemblyVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString();
            string projectName = System.Reflection.Assembly.GetEntryAssembly().GetName().Name;
            this.Text = projectName + " " + assemblyVersion;

        }

        private void enableControlsDisk(bool isValid)
        {
            textBoxSignedImageDisk.Enabled = isValid;
            buttonSignDisk.Enabled = isValid;
            buttonSignDisk.Enabled = isValid;
        }

        private void textBoxImageDisk_TextChanged(object sender, EventArgs e)
        {
            System.Windows.Forms.TextBox textBox = (System.Windows.Forms.TextBox)sender;
            string text = textBox.Text;

            if (!File.Exists(textBoxImageDisk.Text))
            {
                enableControlsDisk(false);
                return;
            }

            //
            // Read Image file to bytes[] bytesImageDisk
            //
            bytesImageDisk = File.ReadAllBytes(textBoxImageDisk.Text);

            if (bytesImageDisk.Length != SIZE_FILE_DISK)
            {
                enableControlsDisk(false);
                return;
            }

            //
            // set the default output image file name
            //
            if (textBoxSignedImageDisk.Text.Length == 0)
            {
                textBoxSignedImageDisk.Text = Path.GetDirectoryName(text) + Path.DirectorySeparatorChar + Path.GetFileNameWithoutExtension(text) + "_signed" + Path.GetExtension(text); ;
            }
            enableControlsDisk(true);
        }

        private void buttonDsaPrivateKey_Click(object sender, EventArgs e)
        {
            textBoxDsaPrivateKey.Text = buttonFilePath_Click(textBoxDsaPrivateKey.Text);
        }

        private void buttonImageBios_Click(object sender, EventArgs e)
        {
            this.openFileDialog1.InitialDirectory = textBoxWorkingFolder.Text;
            textBoxImageBios.Text = buttonFilePath_Click(textBoxImageBios.Text);
        }

        private void buttonSignedImageBios_Click(object sender, EventArgs e)
        {
            textBoxSignedImageBios.Text = buttonFilePath_Click(textBoxSignedImageBios.Text);
        }

        private void buttonUbiosPublicKey_Click(object sender, EventArgs e)
        {
            textBoxUbiosPublicKey.Text = buttonFilePath_Click(textBoxUbiosPublicKey.Text);
        }

        private void buttonUbcPublicKey_Click(object sender, EventArgs e)
        {
            textBoxUbcPublicKey.Text = buttonFilePath_Click(textBoxUbcPublicKey.Text);
        }

        private void buttonBootLoaderPublicKey_Click(object sender, EventArgs e)
        {
            textBoxBootLoaderPublicKey.Text = buttonFilePath_Click(textBoxBootLoaderPublicKey.Text);
        }

        private void buttonHashRemove_Click(object sender, EventArgs e)
        {
            if (listBoxHashUbios.SelectedItems.Count > 0)
            {
                while (listBoxHashUbios.SelectedItems.Count > 0)
                {
                    listBoxHashUbios.Items.Remove(listBoxHashUbios.SelectedItems[0]);
                }
            }
        }

        private void buttonImageDisk_Click(object sender, EventArgs e)
        {
            textBoxImageDisk.Text = buttonFilePath_Click(textBoxImageDisk.Text);
        }

        private void buttonSignedImageDisk_Click(object sender, EventArgs e)
        {
            textBoxSignedImageDisk.Text = buttonFilePath_Click(textBoxSignedImageDisk.Text);
        }

        private void buttonImageUbc_Click(object sender, EventArgs e)
        {
            textBoxImageUbc.Text = buttonFilePath_Click(textBoxImageUbc.Text);
        }

        private void buttonSignedImageUbc_Click(object sender, EventArgs e)
        {
            textBoxSignedImageUbc.Text = buttonFilePath_Click(textBoxSignedImageUbc.Text);
        }

        private void buttonHashAddUbc_Click(object sender, EventArgs e)
        {
            if (listBoxHashUbc.Items.Count == 0)
            {
                var files = Directory.GetFiles(textBoxWorkingFolder.Text, "*.*", SearchOption.AllDirectories);

                foreach (string file in files)
                {
                    var info = new FileInfo(file);
                    if (info.Length == HASH_SIZE)
                    {
                        listBoxHashUbc.Items.Add(info.FullName);
                    }
                }
            }
            else
            {
                string hash_fp = "";
                hash_fp = buttonFilePath_Click(hash_fp);
                if (!String.IsNullOrEmpty(hash_fp))
                {
                    var info = new FileInfo(hash_fp);
                    if (info.Length == HASH_SIZE)
                    {
                        listBoxHashUbc.Items.Add(hash_fp);
                    }
                    else
                    {
                        MessageBox.Show("Hash file size is limited to 20 bytes");
                    }
                }
            }
        }

        private void buttonHashRemoveUbc_Click(object sender, EventArgs e)
        {
            if (listBoxHashUbc.SelectedItems.Count > 0)
            {
                while (listBoxHashUbc.SelectedItems.Count > 0)
                {
                    listBoxHashUbc.Items.Remove(listBoxHashUbc.SelectedItems[0]);
                }
            }
        }

        private byte[] bigIntegersToBytes(Org.BouncyCastle.Math.BigInteger[] bigIntArray)
        {
            byte[][] byteArrays = new byte[bigIntArray.Length][];
            for (int i = 0; i < bigIntArray.Length; i++)
            {
                byteArrays[i] = bigIntArray[i].ToByteArray();
            }

            int totalLength = byteArrays.Sum(x => x.Length);
            byte[] mergedArray = new byte[totalLength];

            int currentIndex = 0;
            foreach (byte[] array in byteArrays)
            {
                Buffer.BlockCopy(array, 0, mergedArray, currentIndex, array.Length);
                currentIndex += array.Length;
            }

            return mergedArray;
        }

        private void buttonSignUbc_Click(object sender, EventArgs e)
        {
            //
            // 0. clear 
            //
            Array.Clear(bytesImageUbc, OFFSET_HASH_LIST_START_UBC, OFFSET_UBIOS_VERSION_UBC - OFFSET_HASH_LIST_START_UBC);
            //
            // 1. hash list
            //
            byte[] hash;
            int offsetRomImage = OFFSET_HASH_LIST_START_UBC;
            foreach (string hashFile in listBoxHashUbc.Items)
            {
                if (File.Exists(hashFile)) 
                {
                    hash = File.ReadAllBytes(hashFile);
                    Buffer.BlockCopy(hash, 0, bytesImageUbc, offsetRomImage, hash.Length);
                    offsetRomImage += hash.Length;
                    // ignore hash files after offset OFFSET_HASH_LIST_END_PLUS1_UBC
                    if (offsetRomImage > OFFSET_HASH_LIST_END_PLUS1_UBC - hash.Length) { break; }
                }
            }
            //
            // 2.  patch UBIOS version string @ OFFSET_UBIOS_VERSION_UBC (length 0x18)
            //
            byte[] VersionString = new byte[0x18];
            byte[] VersionStringInput = Encoding.ASCII.GetBytes(textBoxUbiosVersionUbc.Text);
            // copy input to target array
            Buffer.BlockCopy(VersionStringInput, 0, VersionString, 0, VersionStringInput.Length);
            // override to Image buffer
            Buffer.BlockCopy(VersionString, 0, bytesImageUbc, OFFSET_UBIOS_VERSION_UBC, VersionString.Length);
            //
            // 3. patch UBC version string @ OFFSET_UBC_VERSION (length 0x18)
            //
            byte[] VersionStringUbc = new byte[6];
            byte[] VersionStringInputUbc = Encoding.ASCII.GetBytes(textBoxUbcVersion.Text);
            // copy input to target array
            Buffer.BlockCopy(VersionStringInputUbc, 0, VersionStringUbc, 0, VersionStringInputUbc.Length);
            // override to Image buffer
            Buffer.BlockCopy(VersionStringUbc, 0, bytesImageUbc, OFFSET_UBC_VERSION, VersionStringUbc.Length);
            //
            // 4. Hash & Sign
            //
            byte[] blobUbc = subByteArray(bytesImageUbc, 0, (bytesImageUbc.Length - (HASH_SIZE + SIGNATURE_SIZE)));

            // Compute the hash of the blobUbc
            hashFunction.BlockUpdate(blobUbc, 0, blobUbc.Length);
            hash = new byte[hashFunction.GetDigestSize()];
            hashFunction.DoFinal(hash, 0);
            // Convert the signature to an byte array
            byte[] signature;
            int retryCount = 0;
            do
            {
                signature = bigIntegersToBytes(signer.GenerateSignature(hash));
                retryCount++;
            } while (signature.Length != 40 && retryCount < RETRY_SIGN);
            if (retryCount >= RETRY_SIGN) { return; }

            // patch signature & hash
            Buffer.BlockCopy(hash, 0, bytesImageUbc, bytesImageUbc.Length - (hash.Length + signature.Length), hash.Length); // length = 0x14
            Buffer.BlockCopy(signature, 0, bytesImageUbc, bytesImageUbc.Length - signature.Length, signature.Length); // length = 0x28
            //
            //  3. Write to output file
            //
            try
            {
                MessageBox.Show("Write to " + textBoxSignedImageUbc.Text);
                File.WriteAllBytes(textBoxSignedImageUbc.Text, bytesImageUbc);
            }
            catch (IOException ex)
            {
                MessageBox.Show("An error occurred while writing to the file: " + ex.Message);
            }
        }

        private void textBoxDsaPrivateKey_TextChanged(object sender, EventArgs e)
        {
            if (!File.Exists(textBoxDsaPrivateKey.Text)) { return; }

            string pem = File.ReadAllText(textBoxDsaPrivateKey.Text);

            // Create a PemReader to parse the PEM file
            var reader = new PemReader(new StringReader(pem));

            // Read the private key from the PEM file
            AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)reader.ReadObject();

            // Get the DSA private key from the key pair
            DsaPrivateKeyParameters dsaPrivateKey = (DsaPrivateKeyParameters)keyPair.Private;

            // Create a SHA1 hash function
            hashFunction = new Sha1Digest();

            // Create a DSA signer object
            signer = new DsaSigner();

            // Initialize the signer with the DSA private key
            signer.Init(true, dsaPrivateKey);
        }
    }

}
