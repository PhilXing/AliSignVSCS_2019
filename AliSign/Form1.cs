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

        public const int SIZE_DISK_SECTOR = 512;

        // Common encripto variables
        IDigest hashFunction;
        IDsa signer;
        // for BIOS sign
        public byte[] bytesImageUbios;
        public List<string> listHashUbiosString = new List<string>();
        public int identificationAlignment = 16;
        public bool is1stTime = true;
        // for Disk sign
        public byte[] bytesImageDisk;
        // for UBC sign
        public byte[] bytesImageUbc;
        public List<string> listHashUbcString = new List<string>();

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

            RestoreListBoxFromSettings(listBoxHashFileUbios, "listBoxHashFileUbios");
            RestoreListBoxFromSettings(listBoxHashFileUbc, "listBoxHashFileUbc");

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

            SaveListBoxToSettings(listBoxHashFileUbios, "listBoxHashFileUbios");
            SaveListBoxToSettings(listBoxHashFileUbc, "listBoxHashFileUbc");

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
            if (listBoxHashFileUbios.Items.Count == 0)
            {
                var files = Directory.GetFiles(textBoxWorkingFolder.Text, "*.*", SearchOption.AllDirectories);

                foreach (string file in files)
                {
                    var info = new FileInfo(file);
                    if (info.Length == HASH_SIZE)
                    {
                        listBoxHashFileUbios.Items.Add(info.FullName);
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
                        listBoxHashFileUbios.Items.Add(hash_fp);
                    }
                    else
                    {
                        MessageBox.Show("Hash file size is limited to 20 bytes");
                    }
                }
            }

        }

        private void buttonWorkingFolder_Click(object sender, EventArgs e)
        {
            if (Directory.Exists(textBoxWorkingFolder.Text))
            {
                folderBrowserDialog1.SelectedPath = textBoxWorkingFolder.Text;
            }
            if (folderBrowserDialog1.ShowDialog() == DialogResult.OK)
            {
                textBoxWorkingFolder.Text = folderBrowserDialog1.SelectedPath;
            }
        }

        private void textBoxWorkingFolder_TextChanged(object sender, EventArgs e)
        {
            System.Windows.Forms.TextBox textBox = (System.Windows.Forms.TextBox)sender;
           string text = textBox.Text;

            // Check if the specified folder exists
            if (Directory.Exists(text))
            {
                ResetInputFiles();
            }
        }

        private void ResetInputFiles()
        {
            //
            // clear input files in all tab pages
            //
            textBoxDsaPrivateKey.Text = string.Empty;
            ClearInputFilesUbios();
            textBoxImageDisk.Text = string.Empty;
            ClearInputFilesUbc();

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
                    listBoxHashFileUbios.Items.Add(info.FullName);
                    continue;
                }
                // TODO: confirm the size of the private key
                if ((info.Length == PRIVATE_KEY_SIZE || info.Length == PRIVATE_KEY_SIZE_2) && string.IsNullOrEmpty(textBoxDsaPrivateKey.Text))
                {
                    textBoxDsaPrivateKey.Text = info.FullName;
                    continue;
                }
                if (info.Length == PUBLIC_KEY_SIZE)
                {
                    if (info.Name.ToUpper().Contains("UBC") && string.IsNullOrEmpty(textBoxUbcPublicKey.Text))
                    {
                        textBoxUbcPublicKey.Text = info.FullName;
                        continue;
                    }
                    if (info.Name.ToUpper().Contains("UBIOS") && string.IsNullOrEmpty(textBoxUbiosPublicKey.Text))
                    {
                        textBoxUbiosPublicKey.Text = info.FullName;
                        continue;
                    }
                    if (info.Name.ToUpper().Contains("MBR") && string.IsNullOrEmpty(textBoxBootLoaderPublicKey.Text))
                    {
                        textBoxBootLoaderPublicKey.Text = info.FullName;
                        //continue;
                    }
                    continue;
                }
                //
                // this must be the last guessing onf the tab pag UBIOS, to refine the other file settings
                //
                if (info.Length == SIZE_FILE_BIOS && string.IsNullOrEmpty(textBoxImageBios.Text))
                {
                    textBoxImageBios.Text = info.FullName;
                    continue;
                }
                if (info.Length == SIZE_FILE_DISK && string.IsNullOrEmpty(textBoxImageDisk.Text))
                {
                    textBoxImageDisk.Text = info.FullName;
                    continue;
                }
                if (info.Length == SIZE_FILE_UBC && string.IsNullOrEmpty(textBoxImageUbc.Text))
                {
                    textBoxImageUbc.Text = info.FullName;
                    continue;
                }
            }
            return;
        }

        private long SearchBytes(byte[] needle)
        {
            if (bytesImageUbios == null)
            {
                return -1;
            }
            var len = needle.Length;
            var limit = bytesImageUbios.Length - len;
            for (var i = 0; i <= limit; i += identificationAlignment)
            {
                var k = 0;
                for (; k < len; k++)
                {
                    if (needle[k] != bytesImageUbios[i + k]) break;
                }
                if (k == len) return i;
            }
            return -1;
        }

        private void EnableControlsDsa(bool isValid)
        {
            textBoxImageBios.Enabled = isValid;
            buttonImageBios.Enabled = isValid;
            EnableControlsBios(isValid);
            textBoxImageDisk.Enabled = isValid;
            buttonImageDisk.Enabled = isValid;
            enableControlsDisk(isValid);
            textBoxImageUbc.Enabled = isValid;
            buttonImageUbc.Enabled = isValid;
            enableControlsUbc(isValid);
        }

        private void EnableControlsBios(bool isValid)
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
            buttonRevertHashUbios.Enabled = isValid;
            buttonHashEmbeddedRemove.Enabled = isValid;
            listBoxHashUbios.Enabled = isValid;
            buttonHashAdd.Enabled = isValid;
            buttonHashRemove.Enabled = isValid;
            listBoxHashFileUbios.Enabled = isValid;
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
            if (SearchBytes(AdlinkBiosIdentification1) == -1)
            {
                //MessageBox.Show("This ROM image is not supported 1.");
                return false;
            }
            if (SearchBytes(AdlinkBiosIdentification2) == -1)
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
            var validSignarueOffset = bytesImageUbios.Length - 16;
            var i = 0;
            for (; i < len; i++)
            {
                if (validSignature[i] != bytesImageUbios[i + validSignarueOffset]) break;
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
            buttonRevertHashUbc.Enabled = isValid;
            buttonHashEmbeddedUbcRemove.Enabled = isValid;
            listBoxHashUbc.Enabled = isValid;
            buttonHashAddUbc.Enabled = isValid;
            buttonHashRemoveUbc.Enabled = isValid;
            listBoxHashFileUbc.Enabled = isValid;
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
            // read embedded hashes
            //
            RevertHashEmbedded(listBoxHashUbc, listHashUbcString, bytesImageUbc, OFFSET_HASH_LIST_START_UBC, OFFSET_HASH_LIST_END_PLUS1_UBC);
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
            if (originalArray == null) return null;
            int length = endIndex_1 - startIndex;
            byte[] subsetArray = new byte[length];
            Array.Copy(originalArray, startIndex, subsetArray, 0, length);
            return subsetArray;
        }

        private void RevertHashEmbedded(ListBox listBoxHash, List<string> listHashString, byte[] bytesImage, int OffsetStart, int OffsetEnd)
        {
            // clear data source
            listBoxHash.DataSource = null;
            // rebuild data source
            listHashString.Clear();
            // hash by hash
            for (int i = OffsetStart; i < OffsetEnd - HASH_SIZE + 1; i += HASH_SIZE)
            {
                // if all 0?
                int j;
                for (j = 0; j < HASH_SIZE; j++)
                {
                    if (bytesImage[i + j] != 0 && bytesImage[i + j] != 0xff)
                    {
                        break;
                    }
                }

                if (j < HASH_SIZE) // if not all 0
                {
                    byte[] hash = new byte[HASH_SIZE];
                    Buffer.BlockCopy(bytesImage, i, hash, 0, HASH_SIZE);
                    string hexString = BitConverter.ToString(hash);
                    listHashString.Add(hexString);
                }
                else
                {
                    break;
                }
            }
            // reassign data source
            listBoxHash.DataSource = listHashString;
        }

        private void FilterHashFiles(ListBox listBoxHashEmbedded, ListBox listBoxHashFile)
        {
            if (listBoxHashFile.Items.Count == 0) return;
            foreach (string hexString in listBoxHashEmbedded.Items)
            {
                string[] hexArray = hexString.Split('-');
                byte[] hashEmbedded = hexArray.Select(s => byte.Parse(s, System.Globalization.NumberStyles.HexNumber)).ToArray();
                // remove duplicate hash files
                for (int i = listBoxHashFile.Items.Count - 1; i >= 0; i--)
                {
                    if (String.IsNullOrEmpty(listBoxHashFile.Items[i].ToString()))
                    {
                        listBoxHashFile.Items.RemoveAt(i);
                        continue;
                    }
                    byte[] hash = File.ReadAllBytes(listBoxHashFile.Items[i].ToString());
                    if (hashEmbedded.SequenceEqual(hash))
                    {
                        listBoxHashFile.Items.RemoveAt(i);
                    }
                }
            }
        }

        private void textBoxImageBios_TextChanged(object sender, EventArgs e)
        {
            System.Windows.Forms.TextBox textBox = (System.Windows.Forms.TextBox)sender;
            string text = textBox.Text;

            if (File.Exists(text))
            {
                //
                // Read Image file to bytes[] bytesImageUbios
                //
                bytesImageUbios = File.ReadAllBytes(text);
                //
                // read embedded hashes
                //
                RevertHashEmbedded(listBoxHashUbios, listHashUbiosString, bytesImageUbios, OFFSET_HASH_LIST_START, OFFSET_HASH_LIST_END_PLUS1);
                //
                // support old project which size is 4MB and the identification is not 16 bytes aligned
                //
                //if (bytesImageUbios.Length >= 0x800000)
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
                    textBoxUbiosVersion.Text = System.Text.Encoding.UTF8.GetString(subByteArray(bytesImageUbios, OFFSET_UBIOS_VERSION, (OFFSET_UBIOS_VERSION + textBoxUbiosVersion.MaxLength))).Replace("\0", string.Empty);
                }

                EnableControlsBios(isValidImageBios());
            }
            else
            {
                EnableControlsBios(false);
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
            this.Text = projectName + " " + assemblyVersion + " beta";

        }

        private void enableControlsDisk(bool isValid)
        {
            textBoxSignedImageDisk.Enabled = isValid;
            buttonSignedImageDisk.Enabled = isValid;
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

        private void ListBoxRemoveSelected(ListBox listBox)
        {
            if (listBox.SelectedItems.Count > 0)
            {
                while (listBox.SelectedItems.Count > 0)
                {
                    listBox.Items.Remove(listBox.SelectedItems[0]);
                }
            }
        }

        private void buttonHashRemove_Click(object sender, EventArgs e)
        {
            ListBoxRemoveSelected(listBoxHashFileUbios);
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
            if (listBoxHashFileUbc.Items.Count == 0)
            {
                var files = Directory.GetFiles(textBoxWorkingFolder.Text, "*.*", SearchOption.AllDirectories);

                foreach (string file in files)
                {
                    var info = new FileInfo(file);
                    if (info.Length == HASH_SIZE)
                    {
                        listBoxHashFileUbc.Items.Add(info.FullName);
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
                        listBoxHashFileUbc.Items.Add(hash_fp);
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
            ListBoxRemoveSelected(listBoxHashFileUbc);
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
            // patch embbedded hashes
            foreach (string hexString in listBoxHashUbc.Items)
            {
                string[] hexArray = hexString.Split('-');
                hash = hexArray.Select(s => byte.Parse(s, System.Globalization.NumberStyles.HexNumber)).ToArray();
                Buffer.BlockCopy(hash, 0, bytesImageUbc, offsetRomImage, hash.Length);
                offsetRomImage += hash.Length;
            }
            // patch input hash files
            foreach (string hashFile in listBoxHashFileUbc.Items)
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
            if (checkBoxUbiosVersionUbc.Checked)
            {
                byte[] VersionString = new byte[0x18];
                byte[] VersionStringInput = Encoding.ASCII.GetBytes(textBoxUbiosVersionUbc.Text);
                // copy input to target array
                Buffer.BlockCopy(VersionStringInput, 0, VersionString, 0, VersionStringInput.Length);
                // override to Image buffer
                Buffer.BlockCopy(VersionString, 0, bytesImageUbc, OFFSET_UBIOS_VERSION_UBC, VersionString.Length);
            }
            //
            // 3. patch UBC version string @ OFFSET_UBC_VERSION (length 0x18)
            //
            if (checkBoxUbcVersion.Checked)
            {
                byte[] VersionStringUbc = new byte[6];
                byte[] VersionStringInputUbc = Encoding.ASCII.GetBytes(textBoxUbcVersion.Text);
                // copy input to target array
                Buffer.BlockCopy(VersionStringInputUbc, 0, VersionStringUbc, 0, VersionStringInputUbc.Length);
                // override to Image buffer
                Buffer.BlockCopy(VersionStringUbc, 0, bytesImageUbc, OFFSET_UBC_VERSION, VersionStringUbc.Length);
            }
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
            System.Windows.Forms.TextBox textBox = (System.Windows.Forms.TextBox)sender;
            string text = textBox.Text;

            if (File.Exists(text))
            {
                string pem = File.ReadAllText(text);

                // Create a PemReader to parse the PEM file
                var reader = new PemReader(new StringReader(pem));

                // Read the private key from the PEM file
                AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)reader.ReadObject();

                if (keyPair == null)
                {
                    EnableControlsDsa(false);
                    return;
                }

                // Get the DSA private key from the key pair
                DsaPrivateKeyParameters dsaPrivateKey = (DsaPrivateKeyParameters)keyPair.Private;

                // Create a SHA1 hash function
                hashFunction = new Sha1Digest();

                // Create a DSA signer object
                signer = new DsaSigner();

                // Initialize the signer with the DSA private key
                signer.Init(true, dsaPrivateKey);

                EnableControlsDsa(true);
            }
            else
            {
                EnableControlsDsa(false);
            }
        }

        private void buttonSignDisk_Click(object sender, EventArgs e)
        {
            byte[] signature;
            byte[] hash;
            int retryCount;

            //
            // 1. sign MBR
            // 
            short BL_Ss = 1; // GRUB Boot Loader Start Sector; 
            Buffer.BlockCopy(BitConverter.GetBytes(BL_Ss), 0, bytesImageDisk, 0x1b4, sizeof(short));

            short BL_Si = (short)(BitConverter.ToInt16(bytesImageDisk, 0x1c6) - 2); // BL Si = GRUB Boot Loader Sector Size
            Buffer.BlockCopy(BitConverter.GetBytes(BL_Si), 0, bytesImageDisk, 0x1b6, sizeof(short));

            // assemble a blobMbr
            byte[] blobMbr = subByteArray(bytesImageDisk, 0, 0x178).Concat(subByteArray(bytesImageDisk, 0x1b4, SIZE_DISK_SECTOR)).ToArray();

            // Compute the hash of the blobMbr
            hashFunction.BlockUpdate(blobMbr, 0, blobMbr.Length);
            hash = new byte[hashFunction.GetDigestSize()];
            hashFunction.DoFinal(hash, 0);
            // Convert the signature to an byte array
            retryCount = 0;
            do
            {
                signature = bigIntegersToBytes(signer.GenerateSignature(hash));
                retryCount++;
            } while (signature.Length != 40 && retryCount < RETRY_SIGN);
            if (retryCount >= RETRY_SIGN) { return; }

            // patch signature & hash
            Buffer.BlockCopy(signature, 0, bytesImageDisk, 0x178, signature.Length); // length = 0x28
            Buffer.BlockCopy(hash, 0, bytesImageDisk, 0x178 + signature.Length, hash.Length); // length = 0x14
            //
            // 2. sign GRUB
            //
            byte[] blobGrub = subByteArray(bytesImageDisk, SIZE_DISK_SECTOR, (bytesImageDisk.Length - SIZE_DISK_SECTOR)); // 2nd~eof-1 sector sectors

            // Compute the hash of the blobGrub
            hashFunction.BlockUpdate(blobGrub, 0, blobGrub.Length);
            hashFunction.DoFinal(hash, 0);
            // Convert the signature to an byte array
            retryCount = 0;
            do
            {
                signature = bigIntegersToBytes(signer.GenerateSignature(hash));
                retryCount++;
            } while (signature.Length != 40 && retryCount < RETRY_SIGN);
            if (retryCount >= RETRY_SIGN) { return; }

            // patch signature & hash
            Buffer.BlockCopy(hash, 0, bytesImageDisk, bytesImageDisk.Length - SIZE_DISK_SECTOR, hash.Length); // length = 0x14
            Buffer.BlockCopy(signature, 0, bytesImageDisk, bytesImageDisk.Length - SIZE_DISK_SECTOR + hash.Length, signature.Length); // length = 0x28
            //
            //  3. Write to output file
            //
            try
            {
                MessageBox.Show("Write to " + textBoxSignedImageDisk.Text);
                File.WriteAllBytes(textBoxSignedImageDisk.Text, bytesImageDisk);
            }
            catch (IOException ex)
            {
                MessageBox.Show("An error occurred while writing to the file: " + ex.Message);
            }
        }

        private void buttonSignBios_Click(object sender, EventArgs e)
        {
            //
            // 1. patch UBIOS public key and it's double word - byte checksum to OFFSET_UBIOS_PUBLIC_KEY
            //
            if (checkBoxUbiosPublicKey.Checked)
            {
                byte[] UbiosPublicKey;
                int checksum = 0;
                if (!File.Exists(textBoxUbiosPublicKey.Text)) { return; }
                UbiosPublicKey = File.ReadAllBytes(textBoxUbiosPublicKey.Text);
                Buffer.BlockCopy(UbiosPublicKey, 0, bytesImageUbios, OFFSET_UBIOS_PUBLIC_KEY, UbiosPublicKey.Length);
                for (int i = 0; i < UbiosPublicKey.Length; i++)
                {
                    bytesImageUbios[OFFSET_UBIOS_PUBLIC_KEY + i] = UbiosPublicKey[i];
                    checksum += UbiosPublicKey[i];
                }
                // override checksum after UBIOS Public key
                byte[] bytes = BitConverter.GetBytes(checksum);
                Buffer.BlockCopy(bytes, 0, bytesImageUbios, OFFSET_UBIOS_PUBLIC_KEY + UbiosPublicKey.Length, sizeof(int));
            }
            //
            // 2. patch UBC Public key @ 0x3c (Length 0x194)
            //
            if (checkBoxUbcPublicKey.Checked)
            {
                byte[] UbcPublicKey;
                if (!File.Exists(textBoxUbcPublicKey.Text)) { return; }
                UbcPublicKey = File.ReadAllBytes(textBoxUbcPublicKey.Text);
                Buffer.BlockCopy(UbcPublicKey, 0, bytesImageUbios, OFFSET_UBC_PUBLIC_KEY, UbcPublicKey.Length);
            }
            //
            // 3. patch MBR_GPT_BL_PUBLIC_KEY Public key @ 0x1d0 (Length 0x194)
            //
            if (checkBoxBootLoaderPublicKey.Checked)
            {
                byte[] BootLoaderPublicKey;
                if (!File.Exists(textBoxBootLoaderPublicKey.Text)) { return; }
                BootLoaderPublicKey = File.ReadAllBytes(textBoxBootLoaderPublicKey.Text);
                Buffer.BlockCopy(BootLoaderPublicKey, 0, bytesImageUbios, OFFSET_BOOT_LOADER_PUBLIC_KEY, BootLoaderPublicKey.Length);
            }
            //
            // 4. patch UBIOS version string @ OFFSET_UBIOS_VERSION (length 0x18)
            //
            byte[] VersionString = new byte[0x18];
            byte[] VersionStringInput = Encoding.ASCII.GetBytes(textBoxUbiosVersion.Text);
            // copy input to target array
            Buffer.BlockCopy(VersionStringInput, 0, VersionString, 0, VersionStringInput.Length);
            // override to Image buffer
            Buffer.BlockCopy(VersionString, 0, bytesImageUbios, OFFSET_UBIOS_VERSION, VersionString.Length);
            //
            // 5. patch Hash list @OFFSET_HASH_LIST_START ~ OFFSET_HASH_LIST_END_PLUS1)
            //
            Array.Clear(bytesImageUbios, OFFSET_HASH_LIST_START, OFFSET_HASH_LIST_END_PLUS1 - OFFSET_HASH_LIST_START);
            byte[] hash;
            int offsetRomImage = OFFSET_HASH_LIST_START;
            // patch embbedded hashes
            foreach (string hexString in listBoxHashUbios.Items)
            {
                string[] hexArray = hexString.Split('-');
                hash = hexArray.Select(s => byte.Parse(s, System.Globalization.NumberStyles.HexNumber)).ToArray();
                Buffer.BlockCopy(hash, 0, bytesImageUbios, offsetRomImage, hash.Length);
                offsetRomImage += hash.Length;
            }
            // patch input hash files
            foreach (string hashFile in listBoxHashFileUbios.Items)
            {
                if (!File.Exists(hashFile)) { return; }
                hash = File.ReadAllBytes(hashFile);
                Buffer.BlockCopy(hash, 0, bytesImageUbios, offsetRomImage, hash.Length);
                offsetRomImage += hash.Length;
                // ignore hash files after offset OFFSET_HASH_LIST_END_PLUS1
                if (offsetRomImage > OFFSET_HASH_LIST_END_PLUS1 - hash.Length) { break; }
            }
            //
            // 6. get hash and sign the blob from offset 0x3c~EOF of the image.
            //
            // Dotnet's DSA class doesn't support loading DSA private keys refer to: https://www.reddit.com/r/dotnetcore/comments/tg5pqg/creating_dsa_signature_with_private_key/
            // Switch to BouncyCastle library

            // Compute the hash of the blob
            hashFunction.BlockUpdate(bytesImageUbios, 0x3c, bytesImageUbios.Length - 0x3c);
            hash = new byte[hashFunction.GetDigestSize()];
            hashFunction.DoFinal(hash, 0);

            // Convert the signature to an byte array
            byte[] signature = bigIntegersToBytes(signer.GenerateSignature(hash));

            // patch signature & hash to the head of ROM Image
            Buffer.BlockCopy(signature, 0, bytesImageUbios, 0, signature.Length); // length = 0x28
            Buffer.BlockCopy(hash, 0, bytesImageUbios, signature.Length, hash.Length); // length = 0x14
            //
            //  7. Write to output file
            //
            try
            {
                File.WriteAllBytes(textBoxSignedImageBios.Text, bytesImageUbios);
                MessageBox.Show("Write to " + textBoxSignedImageBios.Text);
            }
            catch (IOException ex)
            {
                MessageBox.Show("An error occurred while writing to the file: " + ex.Message);
            }
        }

        private void SetTooltip(object sender)
        {
            System.Windows.Forms.ListBox listBox = (System.Windows.Forms.ListBox)sender;
            int index = listBox.SelectedIndex;
            if (index != -1)
            {
                string hashFile = listBox.Items[index].ToString();
                if (File.Exists(hashFile))
                {
                    byte[] hash = File.ReadAllBytes(hashFile);
                    string hexString = BitConverter.ToString(hash);
                    toolTip1.SetToolTip(listBox, hexString);
                }
            }
        }

        private void RemoveSelectedHashEmbedded(ListBox listBoxHashEmbedded, List<string> listHashString)
        {
            List<int> selectedIndices = new List<int>();
            foreach (int index in listBoxHashEmbedded.SelectedIndices)
            {
                selectedIndices.Add(index);
            }
            selectedIndices.Reverse();
            foreach (int index in selectedIndices)
            {
                listHashString.RemoveAt(index);
            }
            listBoxHashEmbedded.DataSource = null;
            listBoxHashEmbedded.DataSource = listHashString;
        }

        private void buttonHashEmbeddedRemove_Click(object sender, EventArgs e)
        {
            RemoveSelectedHashEmbedded(listBoxHashUbios, listHashUbiosString);
        }

        private void buttonRevertHashUbios_Click(object sender, EventArgs e)
        {
            RevertHashEmbedded(listBoxHashUbios, listHashUbiosString, bytesImageUbios, OFFSET_HASH_LIST_START, OFFSET_HASH_LIST_END_PLUS1);
        }

        private void buttonRevertHashUbc_Click(object sender, EventArgs e)
        {
            RevertHashEmbedded(listBoxHashUbc, listHashUbcString, bytesImageUbc, OFFSET_HASH_LIST_START_UBC, OFFSET_HASH_LIST_END_PLUS1_UBC);
        }

        private void buttonHashEmbeddedUbcRemove_Click(object sender, EventArgs e)
        {
            RemoveSelectedHashEmbedded(listBoxHashUbc, listHashUbcString);
        }


        private void listBoxHashUbios_SelectedIndexChanged(object sender, EventArgs e)
        {
            FilterHashFiles(listBoxHashUbios, listBoxHashFileUbios);
        }

        private void listBoxHashFileUbios_SelectedIndexChanged(object sender, EventArgs e)
        {
            SetTooltip(sender);
        }

        private void listBoxHashUbc_SelectedIndexChanged(object sender, EventArgs e)
        {
            FilterHashFiles(listBoxHashUbc, listBoxHashFileUbc);
        }

        private void listBoxHashFileUbc_SelectedIndexChanged(object sender, EventArgs e)
        {
            SetTooltip(sender);
        }

        private void textBoxUbiosVersion_TextChanged(object sender, EventArgs e)
        {
            if (bytesImageUbios == null) return;
            string VersionString = System.Text.Encoding.UTF8.GetString(subByteArray(bytesImageUbios, OFFSET_UBIOS_VERSION, (OFFSET_UBIOS_VERSION + textBoxUbiosVersion.MaxLength))).Replace("\0", string.Empty);
            checkBoxUbiosVersion.Checked = !(string.Compare(VersionString, textBoxUbiosVersion.Text) == 0);
        }

        private void textBoxUbiosPublicKey_TextChanged(object sender, EventArgs e)
        {
            if (File.Exists(textBoxUbiosPublicKey.Text) && bytesImageUbios != null)
            {
                byte[] UbiosPublicKeyInFile = File.ReadAllBytes(textBoxUbiosPublicKey.Text);
                byte[] UbiosPublicKey = subByteArray(bytesImageUbios, OFFSET_UBIOS_PUBLIC_KEY, OFFSET_UBIOS_PUBLIC_KEY + UbiosPublicKeyInFile.Length);
                checkBoxUbiosPublicKey.Checked = !UbiosPublicKey.SequenceEqual(UbiosPublicKeyInFile);
            }
            else
            {
                checkBoxUbiosPublicKey.Checked = false;
            }
        }

        private void textBoxUbcPublicKey_TextChanged(object sender, EventArgs e)
        {
            if (File.Exists(textBoxUbcPublicKey.Text) && bytesImageUbios != null)
            {
                byte[] UbcPublicKeyInFile = File.ReadAllBytes(textBoxUbcPublicKey.Text);
                byte[] UbcPublicKey = subByteArray(bytesImageUbios, OFFSET_UBC_PUBLIC_KEY, OFFSET_UBC_PUBLIC_KEY + UbcPublicKeyInFile.Length);
                checkBoxUbcPublicKey.Checked = !UbcPublicKey.SequenceEqual(UbcPublicKeyInFile);
            }
            else
            {
                checkBoxUbiosPublicKey.Checked = false;
            }
        }

        private void textBoxBootLoaderPublicKey_TextChanged(object sender, EventArgs e)
        {
            if (File.Exists(textBoxBootLoaderPublicKey.Text) && bytesImageUbios != null)
            {
                byte[] BootLoaderPublicKeyInFile = File.ReadAllBytes(textBoxBootLoaderPublicKey.Text);
                byte[] BootLoaderPublicKey = subByteArray(bytesImageUbios, OFFSET_BOOT_LOADER_PUBLIC_KEY, OFFSET_BOOT_LOADER_PUBLIC_KEY + BootLoaderPublicKeyInFile.Length);
                checkBoxBootLoaderPublicKey.Checked = !BootLoaderPublicKey.SequenceEqual(BootLoaderPublicKeyInFile);
            }
            else
            {
                checkBoxBootLoaderPublicKey.Checked = false;
            }
        }

        private void ClearInputFilesUbios()
        {
            textBoxImageBios.Text = string.Empty;
            textBoxSignedImageBios.Text = string.Empty;
            textBoxUbiosPublicKey.Text = string.Empty;
            textBoxUbcPublicKey.Text = string.Empty;
            textBoxBootLoaderPublicKey.Text = string.Empty;
            listBoxHashUbios.DataSource = null;
            listBoxHashFileUbios.Items.Clear();
        }

        private void ClearInputFilesUbc()
        {
            textBoxImageUbc.Text = string.Empty;
            textBoxSignedImageUbc.Text = string.Empty;
            listBoxHashUbc.DataSource = null;
            listBoxHashFileUbc.Items.Clear();
        }

        private void textBoxUbiosVersionUbc_TextChanged(object sender, EventArgs e)
        {
            if (bytesImageUbc == null) return;
            string VersionString = System.Text.Encoding.UTF8.GetString(subByteArray(bytesImageUbc, OFFSET_UBIOS_VERSION_UBC, (OFFSET_UBIOS_VERSION_UBC + textBoxUbiosVersionUbc.MaxLength))).Replace("\0", string.Empty);
            checkBoxUbiosVersionUbc.Checked = !(string.Compare(VersionString, textBoxUbiosVersionUbc.Text) == 0);
        }

        private void textBoxUbcVersion_TextChanged(object sender, EventArgs e)
        {
            if (bytesImageUbc == null) return;
            string VersionString = System.Text.Encoding.UTF8.GetString(subByteArray(bytesImageUbc, OFFSET_UBC_VERSION, (OFFSET_UBC_VERSION + textBoxUbcVersion.MaxLength))).Replace("\0", string.Empty);
            checkBoxUbcVersion.Checked = !(string.Compare(VersionString, textBoxUbcVersion.Text) == 0);
        }

        private void buttonClearFilesUbc_Click(object sender, EventArgs e)
        {
            ClearInputFilesUbc();
        }

        private void buttonClearFilesUbios_Click(object sender, EventArgs e)
        {
            ClearInputFilesUbios();
        }
    }
}
