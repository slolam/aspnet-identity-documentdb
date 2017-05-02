using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Microsoft.Azure.Documents;

namespace Simple.AspNetCore.Identity.DocumentDb.Tests
{
    [TestClass]
    public class UserStoreTests
    {
        Mock<IDocumentClient> moqClient;

        [TestInitialize]
        public void Init()
        {

        }
        [TestMethod]
        public void TestMethod1()
        {
        }
    }
}
