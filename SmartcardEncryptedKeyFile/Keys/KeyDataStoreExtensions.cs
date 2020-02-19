using System;
using System.IO;
using System.Text;
using System.Xml;

namespace Episource.KeePass.EKF.Keys {
    public static class KeyDataStoreExtensions {
        public static void WriteToXmlKeyFile(this IKeyDataStore keyData, string filePath) {
            using (var stream = File.Open(filePath, FileMode.Create, FileAccess.Write)) {
                using (var xw = XmlWriter.Create(stream, new XmlWriterSettings() {
                    CloseOutput = false,
                    Encoding = new UTF8Encoding(false, false),
                    Indent = true,
                    IndentChars = "\t",
                    NewLineOnAttributes = false
                })) {
                    xw.WriteStartDocument();
                    xw.WriteStartElement("KeyFile");

                    xw.WriteStartElement("Meta");
                    xw.WriteStartElement("Version");
                    xw.WriteString("1.00");
                    xw.WriteEndElement();
                    xw.WriteEndElement();

                    xw.WriteStartElement("Key");
                    xw.WriteStartElement("Data");
                    xw.WriteString(Convert.ToBase64String(keyData.KeyData.ReadData()));
                    xw.WriteEndElement();
                    xw.WriteEndElement();

                    xw.WriteEndElement();
                    xw.WriteEndDocument();
                }
            }
        }
    }
}