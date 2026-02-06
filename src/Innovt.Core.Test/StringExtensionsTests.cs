using Innovt.Core.Utilities;
using NUnit.Framework;

namespace Innovt.Core.Test
{
    [TestFixture]
    public class StringExtensionsTests
    {
        [Test]
        [TestCase("21.9NM.YJD/0001-70")]
        [TestCase("21.9NM.YJD/J0H0-58")]
        [TestCase("219NMYJDSCZ065")]
        [TestCase("4Y.17V.NPM/0001-56")]
        [TestCase("CJR0JTPK000106")]
        [TestCase("00.308.793/0001-00")]
        [TestCase("00.308.793/4945-10")]
        [TestCase("00308793721517")]
        [TestCase("72937654000157")]
        [TestCase("34.948.216/0001-03")]
        public void IsCnpj_ValidCnpj_ReturnsTrue(string cnpj)
        {
            var result = cnpj.IsCnpj();
            Assert.That(result, Is.True);
        }

        [Test]
        [TestCase("21.9XM.YJD/0001-70")]
        [TestCase("21.9NL.YJD/J0H0-58")]
        [TestCase("219NMYJDSCZ165")]
        [TestCase("XY.17V.NPO/0001-56")]
        [TestCase("CJR0JTLK000106")]
        [TestCase("00.123.793/0001-00")]
        [TestCase("00.308.954/4145-10")]
        [TestCase("00308793721518")]
        [TestCase("72937654000159")]
        [TestCase("34.943.226/0001-03")]
        public void IsCnpj_InvalidCnpj_ReturnsFalse(string cnpj)
        {
            var result = cnpj.IsCnpj();
            Assert.That(result, Is.False);
        }

        [Test]
        [TestCase("219NMYJD000170", "21.9NM.YJD/0001-70")]
        [TestCase("219NMYJDJ0H058", "21.9NM.YJD/J0H0-58")]
        [TestCase("4Y17VNPM000156", "4Y.17V.NPM/0001-56")]
        [TestCase("00308793000100", "00.308.793/0001-00")]
        [TestCase("00308793494510", "00.308.793/4945-10")]
        [TestCase("34948216000103", "34.948.216/0001-03")]
        public void FormatCnpj_UnformattedCnpj_ReturnsFormatted(string unformattedCnpj, string expectedFormattedCnpj)
        {
            var result = unformattedCnpj.FormatCnpj();
            Assert.That(result, Is.EqualTo(expectedFormattedCnpj));
        }
    }
}