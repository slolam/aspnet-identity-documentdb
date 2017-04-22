using System;
using Microsoft.Azure.Documents;
using Moq;
using Simple.AspNet.Identity.DocumentDb.Models;
using System.Security.Claims;
using Microsoft.AspNet.Identity;
using Microsoft.Azure.Documents.Client;
using NUnit.Framework;
using System.Threading.Tasks;

namespace Simple.AspNet.Identity.DocumentDb.Tests
{
    [TestFixture]
    public class UserStoreTests
    {
        Mock<IDocumentClient> moqClient;
        UserStore<IdentityUser> userStore;


        [OneTimeSetUp]
        public void Initialize()
        {
            moqClient = new Mock<IDocumentClient>();
            userStore = new UserStore<IdentityUser>(moqClient.Object, "users", "users");
        }

        [Test]
        public async Task UserStore_AddClaimsAsync_AddNewClaim()
        {
            var identity = new IdentityUser();
            var claim = new Claim(ClaimTypes.Role, "Test");
            await userStore.AddClaimAsync(identity, claim);
            Assert.AreEqual(identity.Claims.Count, 1);
            Assert.AreSame(identity.Claims[0].Type, claim.Type);
            Assert.AreSame(identity.Claims[0].Value, claim.Value);
        }

        [Test]
        public async Task UserStore_AddClaimsAsync_ExistingClaim()
        {
            var identity = new IdentityUser();
            var claim = new Claim(ClaimTypes.Role, "Test");
            identity.Claims.Add(new IdentityUserClaim { Type = claim.Type, Value = claim.Value, ValueType = claim.ValueType, Issuer = claim.Issuer, OriginalIssuer = claim.OriginalIssuer });
            await userStore.AddClaimAsync(identity, claim);
            Assert.AreEqual(identity.Claims.Count, 1);
            Assert.AreNotSame(identity.Claims[0], claim);
            Assert.AreEqual(identity.Claims[0].Type, claim.Type);
            Assert.AreEqual(identity.Claims[0].Value, claim.Value);
        }

        [Test]
        public async Task UserStore_AddClaimsAsync_NullUser()
        {
            var identity = new IdentityUser();
            var claim = new Claim(ClaimTypes.Role, "Test");
            identity.Claims.Add(new IdentityUserClaim { Type = claim.Type, Value = claim.Value });
            Assert.ThrowsAsync<ArgumentNullException>(async () =>
            {
                await userStore.AddClaimAsync(null, claim);
            });
        }

        [Test]
        public async Task UserStore_AddClaimsAsync_NullClaim()
        {
            var identity = new IdentityUser();
            var claim = new Claim(ClaimTypes.Role, "Test");
            identity.Claims.Add(new IdentityUserClaim { Type = claim.Type, Value = claim.Value });
            Assert.ThrowsAsync<ArgumentNullException>(async () =>
            {
                await userStore.AddClaimAsync(identity, null);
            });
        }

        [Test]
        public async Task UserStore_AddLoginAsync_AddNewLogin()
        {
            var identity = new IdentityUser();
            var login = new UserLoginInfo("Provider", "Key");
            await userStore.AddLoginAsync(identity, login);
            Assert.AreEqual(identity.Logins.Count, 1);
            Assert.AreSame(identity.Logins[0].LoginProvider, login.LoginProvider);
            Assert.AreSame(identity.Logins[0].ProviderKey, login.ProviderKey);
        }

        [Test]
        public async Task UserStore_AddLoginAsync_ExistingLogin()
        {
            var identity = new IdentityUser();
            var login = new UserLoginInfo("Provider", "Key");
            identity.Logins.Add(new UserLoginInfo(login.LoginProvider, login.ProviderKey));
            await userStore.AddLoginAsync(identity, login);
            Assert.AreEqual(identity.Logins.Count, 1);
            Assert.AreNotSame(identity.Logins[0], login);
            Assert.AreEqual(identity.Logins[0].LoginProvider, login.LoginProvider);
            Assert.AreEqual(identity.Logins[0].ProviderKey, login.ProviderKey);
        }

        [Test]
        public async Task UserStore_AddLoginAsync_UserNull()
        {
            var identity = new IdentityUser();
            var login = new UserLoginInfo("Provider", "Key");
            identity.Logins.Add(new UserLoginInfo(login.LoginProvider, login.ProviderKey));
            Assert.ThrowsAsync<ArgumentNullException>(async () =>
            {
                await userStore.AddLoginAsync(null, login);
            });
        }

        [Test]
        public async Task UserStore_AddLoginAsync_LoginNull()
        {
            var identity = new IdentityUser();
            var login = new UserLoginInfo("Provider", "Key");
            identity.Logins.Add(new UserLoginInfo(login.LoginProvider, login.ProviderKey));
            Assert.ThrowsAsync<ArgumentNullException>(async () =>
            {
                await userStore.AddLoginAsync(identity, null);
            });
        }
        [Test]
        public async Task UserStore_AddToRoleAsync_AddNewRole()
        {
            var identity = new IdentityUser();
            var role = "NewRole";
            await userStore.AddToRoleAsync(identity, role);
            Assert.AreEqual(identity.Roles.Count, 1);
            Assert.AreSame(identity.Roles[0], role);
        }

        [Test]
        public async Task UserStore_AddToRoleAsync_ExistingRole()
        {
            var identity = new IdentityUser();
            var role = "ExistingRole";
            identity.Roles.Add("ExistingRole");
            await userStore.AddToRoleAsync(identity, role);
            Assert.AreEqual(identity.Roles.Count, 1);
            Assert.AreEqual(identity.Roles[0], role);
        }

        [Test]
        public async Task UserStore_AddToRoleAsync_UserNull()
        {
            var identity = new IdentityUser();
            var role = "ExistingRole";
            identity.Roles.Add("ExistingRole");
            Assert.ThrowsAsync<ArgumentNullException>(async () =>
            {
                await userStore.AddToRoleAsync(null, role);
            });
        }

        [Test]
        public async Task UserStore_AddToRoleAsync_RoleNull()
        {
            var identity = new IdentityUser();
            var role = "ExistingRole";
            identity.Roles.Add("ExistingRole");
            Assert.ThrowsAsync<ArgumentException>(async () =>
            {
                await userStore.AddToRoleAsync(identity, null);
            });
        }

        [Test]
        public async Task UserStore_CreateAsync_CreatesUser()
        {
            var identity = new IdentityUser
            {
                UserName = "userNAME",
                Email = "user@domain.com"
            };
            moqClient.Setup(u => u.CreateDocumentAsync(It.IsAny<Uri>(), It.IsAny<object>(), It.IsAny<RequestOptions>(), It.IsAny<bool>()))
                .ReturnsAsync(new ResourceResponse<Document>
                {
                    
                });
            await userStore.CreateAsync(identity);
            Assert.IsNotNull(identity.Id);
        }
    }
}
