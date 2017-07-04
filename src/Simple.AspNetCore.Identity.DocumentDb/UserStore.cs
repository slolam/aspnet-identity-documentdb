using Simple.AspNetCore.Identity.DocumentDb.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Azure.Documents;
using Microsoft.Azure.Documents.Client;
using Microsoft.Azure.Documents.Linq;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

namespace Simple.AspNetCore.Identity.DocumentDb
{
    /// <summary>
    /// Parameters for the DocumentDb source for the identity data store
    /// </summary>
    public class DocumentDbOptions
    {
        /// <summary>
        /// Endpoint of the Azure DocumentDb
        /// </summary>
        public Uri AccountEndpoint { get; set; }

        /// <summary>
        /// Authentication key having read/write privilege to the Azure DocumentDb
        /// </summary>
        public string AccountKey { get; set; }

        /// <summary>
        /// Name of the Azure DocumentDb database
        /// </summary>
        public string Database { get; set; }


        /// <summary>
        /// Name of the Azure DocumentDb Collection
        /// </summary>
        public string Collection { get; set; }

        /// <summary>
        /// Singleton client
        /// </summary>
        internal IDocumentClient Client { get; set; }

        /// <summary>
        /// Gets or sets the connection mode of the <see cref="DocumentClient"/>
        /// </summary>
        /// <remarks>The default value <see cref="ConnectionMode.Direct"/></remarks>
        public ConnectionMode Mode { get; set; } = ConnectionMode.Direct;

        /// <summary>
        /// Gets or sets the connection protocol of the <see cref="DocumentClient"/>
        /// </summary>
        /// <remarks>The default value <see cref="Protocol.Tcp"/></remarks>
        public Protocol Protocol { get; set; } = Protocol.Tcp;
    }

    /// <summary>
    /// Azure DocumentDb identity user store implementation 
    /// </summary>
    /// <typeparam name="TUser">Identity user</typeparam>
    public class UserStore<TUser> : IUserLoginStore<TUser>, IUserClaimStore<TUser>, IUserRoleStore<TUser>, IUserPasswordStore<TUser>,
        IUserSecurityStampStore<TUser>, IUserStore<TUser>, IUserEmailStore<TUser>, IUserLockoutStore<TUser>,
        IUserTwoFactorStore<TUser>, IUserPhoneNumberStore<TUser>, IQueryableUserStore<TUser>, IDisposable
        where TUser : IdentityUser
    {
        /// <summary>
        /// Flag to indicate whether this instance is disposed
        /// </summary>
        private bool _disposed;

        /// <summary>
        /// Name of the Azure DocumentDb database
        /// </summary>
        private readonly string _database;

        /// <summary>
        /// Name of the collection in the Azure DocumentDb database
        /// </summary>
        private readonly string _collection;

        /// <summary>
        /// URI to the Azure DocumentDb collection
        /// </summary>
        private readonly Uri _documentCollection;

        /// <summary>
        /// Collection query options 
        /// </summary>
        private readonly FeedOptions _feedOption = new FeedOptions { EnableCrossPartitionQuery = true, MaxItemCount = 1 };

        /// <summary>
        /// Document client reference to access Azure DocumentDb collection
        /// </summary>
        private readonly IDocumentClient _client;

        /// <summary>
        /// Caching of the current user to optimize the calls to Azure DocumentDb
        /// </summary>
        private TUser _user;


        /// <summary>
        /// Initializes a new instance of the <see cref="UserStore{TUser}"/> class.
        /// </summary>
        /// <param name="options"><see cref="DocumentDbOptions"/> option to collect to the uesr store in Azure DocumentDb</param>
        /// <remarks>It is highly recommended to create database and collection in advance with the required Request Units (RUs) and use /id as partition key</remarks>
        public UserStore(DocumentDbOptions options)
            : this(options.Client ?? (options.Client = new DocumentClient(options?.AccountEndpoint, options?.AccountKey, 
                        new ConnectionPolicy { ConnectionMode = options.Mode, ConnectionProtocol = options.Protocol })), 
                  options?.Database, options?.Collection)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserStore{TUser}"/> class.
        /// </summary>
        /// <param name="client">Instance of the <seealso cref="IDocumentClient"/> implementation to access the Azure DocumentDb</param>
        /// <param name="database">Name of the Azure DocumentDb database</param>
        /// <param name="collection">Name of the Azure DocumentDb collection</param>
        /// <remarks>It is highly recommended to create database and collection in advance with the required Request Units (RUs) and use /id as partition key</remarks>
        public UserStore(IDocumentClient client, string database, string collection)
        {
            client.NotNull(nameof(client));
            database.NotNullOrEmpty(nameof(database), "Invalid database name");
            collection.NotNullOrEmpty(nameof(collection), "Invalid collection name");

            _client = client;
            _database = database;
            _collection = collection;
            _documentCollection = UriFactory.CreateDocumentCollectionUri(_database, _collection);

            //if (options != null)
            //{
            //    Task.Run(async () =>
            //    {
            //        await CreateDatabaseIfNotExistsAsync();
            //        await CreateCollectionIfNotExistsAsync(options);
            //    }).Wait();
            //}

        }

        /// <summary>
        /// Creates the database if not exists asynchronously.
        /// </summary>
        /// <returns>Returns the waitable task</returns>
        private async Task CreateDatabaseIfNotExistsAsync()
        {
            try
            {
                var database = await _client.ReadDatabaseAsync(_database);
            }
            catch (DocumentClientException ex)
            {
                if (ex.StatusCode == System.Net.HttpStatusCode.NotFound) await _client.CreateDatabaseAsync(new Database { Id = _database });
            }
        }

        /// <summary>
        /// Creates the collection if not exists asynchronously.
        /// </summary>
        /// <param name="options">Request options to create the collection if it does not already exist</param>
        /// <returns>Returns the waitable task</returns>
        /// <remarks>By default when a collection is created, it uses <c>id</c> for partitioning the collection for performacec and scalability</remarks>
        private async Task CreateCollectionIfNotExistsAsync(RequestOptions options)
        {
            try
            {
                await _client.ReadDocumentCollectionAsync(_documentCollection);
            }
            catch (DocumentClientException de)
            {
                if (de.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    var indexPolicy = new IndexingPolicy
                    {
                        Automatic = true
                    };

                    var index = new IncludedPath { Path = "/Email/?" };
                    index.Indexes.Add(new RangeIndex(DataType.String, -1));
                    indexPolicy.IncludedPaths.Add(index);

                    index = new IncludedPath { Path = "/UserName/?" };
                    index.Indexes.Add(new RangeIndex(DataType.String, -1));
                    indexPolicy.IncludedPaths.Add(index);

                    index = new IncludedPath { Path = "/Logins/*" };
                    index.Indexes.Add(new RangeIndex(DataType.String, -1));
                    indexPolicy.IncludedPaths.Add(index);

                    index = new IncludedPath { Path = "/*" };
                    index.Indexes.Add(new RangeIndex(DataType.String, -1));
                    index.Indexes.Add(new RangeIndex(DataType.Number, -1));
                    indexPolicy.IncludedPaths.Add(index);

                    var collection = new DocumentCollection { Id = _collection };
                    collection.PartitionKey.Paths.Add("/id");
                    collection.IndexingPolicy = indexPolicy;

                    await _client.CreateDocumentCollectionAsync(
                            UriFactory.CreateDatabaseUri(_database),
                            collection,
                            options);

                    return;
                }
            }
        }

        /// <summary>
        /// Gets the user based on the specified predicate.
        /// </summary>
        /// <param name="predicate">Predicate to retrieve the user</param>
        /// <returns>Returns the identity user asynchronously</returns>
        private async Task<TUser> GetUser(Expression<Func<TUser, bool>> predicate, CancellationToken token)
        {
            var query = _client.CreateDocumentQuery<TUser>(_documentCollection, _feedOption)
                .Where(predicate)
                .Take(1)
                .AsDocumentQuery();

            if (query.HasMoreResults)
            { 
                token.ThrowIfCancellationRequested();
                var resp = await query.ExecuteNextAsync<TUser>();
                if (_feedOption.SessionToken == null) _feedOption.SessionToken = resp.SessionToken;
                return resp.FirstOrDefault();
            }
            return null;
        }

        /// <summary>
        /// Gets the user based on the specified predicate.
        /// </summary>
        /// <param name="predicate">Predicate to retrieve the user</param>
        /// <returns>Returns the identity user asynchronously</returns>
        private async Task<List<TUser>> GetUsers(Expression<Func<TUser, bool>> predicate, CancellationToken token)
        {
            var query = _client.CreateDocumentQuery<TUser>(_documentCollection, _feedOption)
                .Where(predicate)
                .AsDocumentQuery();
            var users = new List<TUser>();
            while (query.HasMoreResults)
            {
                token.ThrowIfCancellationRequested();
                var resp = await query.ExecuteNextAsync<TUser>();
                users.AddRange(resp);
            }
            return users;
        }




        /// <summary>
        /// Adds the login to the identity user.
        /// </summary>
        /// <param name="user">The identity user.</param>
        /// <param name="login">The login details</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a waitable task</returns>
        public Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));
            login.NotNull(nameof(login));
            login.LoginProvider.NotNullOrEmpty(nameof(login.LoginProvider), "Invalid login provider");

            if (!user.Logins.Any(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey))
            {
                user.Logins.Add(new IdentityLoginInfo { LoginProvider = login.LoginProvider, ProviderKey = login.ProviderKey });
            }

            return Task.FromResult(0);
        }

        /// <summary>
        /// Retrieves the identity user from Azure DocumentDb based on the login information
        /// </summary>
        /// <param name="loginProvider">Login information</param>
        /// <param name="providerKey">Provider key</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns identity user associated with the login if exists, else null</returns>
        public async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken token)
        {
            ThrowIfDisposed();

            loginProvider.NotNull(nameof(loginProvider));
            providerKey.NotNull(nameof(providerKey));

            if (_user != null && _user.Logins.Any(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey))
                return _user.Clone();

            _user = await GetUser(user => user.Logins.Contains(new IdentityLoginInfo { LoginProvider = loginProvider, ProviderKey = providerKey }), token);
            return _user.Clone();
        }


        /// <summary>
        /// Gets the list of the logins for the identity user
        /// </summary>
        /// <param name="user">The identity user</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns the list of the logins</returns>
        public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            var logins = user.Logins.Select(u => new IdentityLoginInfo { LoginProvider = u.LoginProvider, ProviderKey = u.ProviderKey }).ToList() as IList<UserLoginInfo>;
            return Task.FromResult(logins);
        }


        /// <summary>
        /// Removes the login information from the user.
        /// </summary>
        /// <param name="user">Identity user from which the login information is to be removed</param>
        /// <param name="loginProvider">Login information to be removed</param>
        /// <param name="providerKey">Provider key for the login</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a waitable task</returns>
        public Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));
            loginProvider.NotNull(nameof(loginProvider));
            providerKey.NotNull(nameof(providerKey));


            user.Logins.RemoveAll(u => u.LoginProvider == loginProvider && u.ProviderKey == providerKey);

            return Task.FromResult(0);
        }

        /// <summary>
        /// Create a new identity user in the Azure DocumentDb collection
        /// </summary>
        /// <param name="user">Identity user to be created</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a waitable task</returns>
        public async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            if (string.IsNullOrEmpty(user.Id))
            {
                user.Id = Guid.NewGuid().ToString();
            }

            //Azure DocumentDb is case sensitive No SQL, hence maintain a normalized (lower) case for better index
            user.Id = user?.Id?.ToLowerInvariant();
            //user.Email = user?.Email?.ToLowerInvariant();
            //user.UserName = user?.UserName?.ToLowerInvariant();

            var response = await _client.CreateDocumentAsync(_documentCollection, user, new RequestOptions { SessionToken = _feedOption.SessionToken });
            if (_feedOption.SessionToken == null) _feedOption.SessionToken = response.SessionToken;
            _user = user.Clone();

            return await Task.FromResult(IdentityResult.Success);
        }

        /// <summary>
        /// Delete a user from the Azure DocumentDb collection
        /// </summary>
        /// <param name="user">Identity user to be deleted</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a waitable task</returns>
        public async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            user.Id = user?.Id?.ToLowerInvariant();

            try
            {
                var resp = await _client.ReadDocumentAsync(UriFactory.CreateDocumentUri(_database, _collection, user.Id), new RequestOptions { PartitionKey = new PartitionKey(user.Id), SessionToken = _feedOption.SessionToken });
                if (resp != null && resp.Resource != null)
                {
                    await _client.DeleteDocumentAsync(resp.Resource.SelfLink);
                    _user = null;
                    return await Task.FromResult(IdentityResult.Success);
                }
            }
            catch (DocumentClientException dce)
            {
                if (dce.StatusCode == System.Net.HttpStatusCode.NotFound) return await Task.FromResult(IdentityResult.Failed(new IdentityError { Code = "404", Description = "User not found!" }));
                throw;
            }

            return await Task.FromResult(IdentityResult.Failed(new IdentityError { Code = "404", Description = "User not found!" }));
        }

        /// <summary>
        /// Finds a identity user by id in the Azure DocumentDb collection
        /// </summary>
        /// <param name="userId">Identity user identifer</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns the identity user if exists, else null</returns>
        public async Task<TUser> FindByIdAsync(string userId, CancellationToken token)
        {
            ThrowIfDisposed();

            userId.NotNullOrEmpty(nameof(userId), "Invalid user id");

            if (string.Compare(userId, _user?.Id, StringComparison.CurrentCultureIgnoreCase) == 0)
                return _user.Clone();

            userId = userId.ToLowerInvariant();
            try
            {
                token.ThrowIfCancellationRequested();
                var resp = await _client.ReadDocumentAsync(UriFactory.CreateDocumentUri(_database, _collection, userId), new RequestOptions { PartitionKey = new PartitionKey(userId), SessionToken = _feedOption.SessionToken });
                if (resp.SessionToken == null) _feedOption.SessionToken = resp.SessionToken;
                _user = (dynamic)resp.Resource;
                return _user.Clone();
            }
            catch (DocumentClientException de)
            {
                if (de.StatusCode == System.Net.HttpStatusCode.NotFound) return null;
                throw;
            }
        }

        /// <summary>
        /// Finds a identity user by name in the Azure DocumentDb collection
        /// </summary>
        /// <param name="userName">User name to the searched in Azure DocumentDb collection</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns the identity user if exist, else null</returns>
        public async Task<TUser> FindByNameAsync(string userName, CancellationToken token)
        {
            ThrowIfDisposed();

            userName.NotNullOrEmpty(nameof(userName), "Invalid user name");

            if (string.Compare(userName, _user?.NormalizedUserName, StringComparison.CurrentCultureIgnoreCase) == 0)
                return _user.Clone();

            _user = await GetUser(user => user.NormalizedUserName == userName, token);
            return _user.Clone();
        }

        /// <summary>
        /// Updates the identity user in the Azure DocumentDb
        /// </summary>
        /// <param name="user">Identity user to be updated</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a waitable task</returns>
        public async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken token)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            return await UpdateUserAsync(user, token);
        }

        /// <summary>
        /// Adds the claim to the identity user.
        /// </summary>
        /// <param name="user">Identity user</param>
        /// <param name="claims">Claim to be added to identity user</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a waitable task</returns>
        public Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));
            claims.NotNull(nameof(claims));

            foreach (var claim in claims)
            {
                if (!user.Claims.Any(c => c.Type == claim.Type && c.Value == claim.Value && c.ValueType == claim.ValueType && c.Issuer == claim.Issuer && c.OriginalIssuer == claim.OriginalIssuer))
                {
                    user.Claims.Add(claim.ToClaim());
                }
            }

            return Task.FromResult(0);
        }

        /// <summary>
        /// Gets the list of the claims for the identity user
        /// </summary>
        /// <param name="user">The identity user</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns the list of the claims for the identity user</returns>

        public Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            IList<Claim> result = user.Claims.Select(c => c.ToClaim()).ToList();
            return Task.FromResult(result);
        }

        /// <summary>
        /// Gets all the users having a claim
        /// </summary>
        /// <param name="claim">Claim to check agains all the user</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns the list of the users having the given claim</returns>
        public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken token)
        {
            ThrowIfDisposed();

            claim.NotNull(nameof(claim));

            return await GetUsers(user => user.Claims.Contains(claim.ToClaim()), token);
        }

        /// <summary>
        /// Removes the claim from the identity user.
        /// </summary>
        /// <param name="user">The identity user from which claim needs to be removed</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <param name="claim">Claim to be removed</param>
        /// <returns>Returns a waitable task</returns>
        public Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));
            claims.NotNull(nameof(claims));

            user.Claims.RemoveAll(claim => claims.Any(c => c.Type == claim.Type && c.Value == claim.Value && c.ValueType == claim.ValueType && c.Issuer == claim.Issuer && c.OriginalIssuer == claim.OriginalIssuer));
            return Task.FromResult(0);
        }


        /// <summary>
        /// Replaces the old claim with the new claim for the user
        /// </summary>
        /// <param name="user">User identity</param>
        /// <param name="claim">Old claim to be replaced</param>
        /// <param name="newClaim">New claim to be added</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns></returns>
        public Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));
            claim.NotNull(nameof(claim));
            newClaim.NotNull(nameof(newClaim));

            if(user.Claims.RemoveAll(c => c.Type == claim.Type && c.Value == claim.Value && c.ValueType == claim.ValueType && c.Issuer == claim.Issuer && c.OriginalIssuer == claim.OriginalIssuer) > 0)
            {
                user.Claims.Add(newClaim.ToClaim());
            }

            return Task.FromResult(0);
        }

        /// <summary>
        /// Adds role to the identity user.
        /// </summary>
        /// <param name="user">The identity user.</param>
        /// <param name="roleName">Name of the role.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a waitable task</returns>
        public Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));
            roleName.NotNullOrEmpty(nameof(roleName), "Invalid role name");

            if (!user.Roles.Any(x => x.Equals(roleName)))
            {
                user.Roles.Add(roleName);
            }

            return Task.FromResult(0);
        }

        /// <summary>
        /// Gets the list of roles for the identity user
        /// </summary>
        /// <param name="user">The identity user</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns list of the roles of the identity user</returns>
        public Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            var result = user.Roles.ToList();

            return Task.FromResult(result as IList<string>);
        }

        /// <summary>
        /// Determines whether the given role is in the identity user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="roleName">Name of the role.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns whether identity user has role or not</returns>
        public Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));
            roleName.NotNull(nameof(roleName));

            return Task.FromResult(user.Roles.Any(r => string.Compare(r, roleName, StringComparison.CurrentCultureIgnoreCase) == 0));
        }

        /// <summary>
        /// Gets the list of the users contains the role
        /// </summary>
        /// <param name="roleName">The role name</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns the list of the users</returns>
        public async Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken token)
        {
            ThrowIfDisposed();

            roleName.NotNull(nameof(roleName));

            return await GetUsers(user => user.Roles.Contains(roleName), token);
        }


        /// <summary>
        /// Removes the role from the identity user.
        /// </summary>
        /// <param name="user">The identity user.</param>
        /// <param name="roleName">Name of the role to be removed.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a waitable task</returns>
        public Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));
            roleName.NotNullOrEmpty(nameof(roleName), "Invalid role name");

            user.Roles.RemoveAll(r => string.Compare(r, roleName, StringComparison.CurrentCultureIgnoreCase) == 0);
            return Task.FromResult(0);
        }

        /// <summary>
        /// Gets the password hash for the identity user
        /// </summary>
        /// <param name="user">The identity user</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns password hash of the identity user</returns>
        public Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            return Task.FromResult(user.PasswordHash);
        }

        /// <summary>
        /// Returns whether the identity user has a password
        /// </summary>
        /// <param name="user">The identity user</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns whether user has password set</returns>
        public Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            return Task.FromResult(user.PasswordHash != null);
        }

        /// <summary>
        /// Sets the password hash for the identity user.
        /// </summary>
        /// <param name="user">The identity user.</param>
        /// <param name="passwordHash">The password hash.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a waitable task</returns>
        public Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            user.PasswordHash = passwordHash;

            return Task.FromResult(0);
        }

        /// <summary>
        /// Gets the security stamp for the identity user.
        /// </summary>
        /// <param name="user">The identity user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns the security stamp for the identity user</returns>
        public Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            return Task.FromResult(user.SecurityStamp);
        }

        /// <summary>
        /// Sets the security stamp on the identity user.
        /// </summary>
        /// <param name="user">The identity user.</param>
        /// <param name="stamp">The stamp.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a waitable task</returns>
        public Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            user.SecurityStamp = stamp;

            return Task.FromResult(0);
        }

        /// <summary>
        /// Finds the identity user by email.
        /// </summary>
        /// <param name="email">The email.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns the identity user associated with the email, else null</returns>
        public async Task<TUser> FindByEmailAsync(string email, CancellationToken token)
        {
            ThrowIfDisposed();

            email.NotNullOrEmpty(nameof(email), "Invalid email");

            if (string.Compare(email, _user?.NormalizedEmail, StringComparison.CurrentCultureIgnoreCase) == 0)
                return _user.Clone();

            //email = email.ToLowerInvariant();

            _user = await GetUser(user => user.NormalizedEmail == email, token);
            return _user.Clone();
        }

        /// <summary>
        /// Gets the email for the identity user.
        /// </summary>
        /// <param name="user">The indeitity user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns email for the identity user</returns>
        public Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            return Task.FromResult(user.Email);
        }

        /// <summary>
        /// Gets the whether email is confirmed for the identity user.
        /// </summary>
        /// <param name="user">The identity user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns whether email is confirmed</returns>
        public Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            return Task.FromResult(user.EmailConfirmed);
        }

        /// <summary>
        /// Sets the email for the identity user.
        /// </summary>
        /// <param name="user">The identity user.</param>
        /// <param name="email">The email.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a awaitable task</returns>
        public Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));
            email.NotNullOrEmpty(nameof(email), "Invalid email address");

            user.Email = email.ToLowerInvariant();

            return Task.FromResult(0);
        }

        /// <summary>
        /// Sets the email confirmed asynchronous.
        /// </summary>
        /// <param name="user">The identity user.</param>
        /// <param name="confirmed">if set to <c>true</c> [confirmed].</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a waitable task</returns>
        public Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            user.EmailConfirmed = confirmed;

            return Task.FromResult(0);
        }

        /// <summary>
        /// Returns the current number of failed access attempts.  This number usually will be reset whenever the password is
        /// verified or the account is locked out.
        /// </summary>
        /// <param name="user">The identity user</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns the failed counts of the identity user</returns>
        public Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            return Task.FromResult(user.AccessFailedCount);
        }

        /// <summary>
        /// Returns whether the user can be locked out.
        /// </summary>
        /// <param name="user">The identity user</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns whether user can be locked out</returns>
        public Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            return Task.FromResult(user.LockoutEnabled);
        }

        /// <summary>
        /// Returns the DateTimeOffset that represents the end of a user's lockout, any time in the past should be considered
        /// not locked out.
        /// </summary>
        /// <param name="user">The identity user</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns the data time that represents the end of a user's lockout</returns>
        public Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            return Task.FromResult(user.LockoutEnd);
        }

        /// <summary>
        /// Used to record when an attempt to access the user has failed
        /// </summary>
        /// <param name="user">The identity user</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns the failed login attempt count of the user</returns>
        public Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            user.AccessFailedCount++;

            return Task.FromResult(user.AccessFailedCount);
        }

        /// <summary>
        /// Used to reset the access failed count, typically after the account is successfully accessed
        /// </summary>
        /// <param name="user">The identity user</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a waitable task</returns>
        public Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            user.AccessFailedCount = 0;
            user.LastLoginAt = DateTime.UtcNow;

            return Task.FromResult(0);
        }

        /// <summary>
        /// Sets whether the user can be locked out.
        /// </summary>
        /// <param name="user">The identity user</param>
        /// <param name="enabled">True to enabled, else false</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a waitable task</returns>
        public Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            user.LockoutEnabled = enabled;

            return Task.FromResult(0);
        }

        /// <summary>
        /// Locks a user out until the specified end date (set to a past date, to unlock a user)
        /// </summary>
        /// <param name="user">The identity user</param>
        /// <param name="lockoutEnd">Future date to lock the user until then, else past date for unlock</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns the waitable task</returns>
        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            user.LockoutEnd = lockoutEnd;

            return Task.FromResult(0);
        }

        /// <summary>
        /// Returns whether two factor authentication is enabled for the user
        /// </summary>
        /// <param name="user">The identity user</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Aschynchronously returns whether two factor authnetication is enabled. true if enabled, else false</returns>
        public Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            return Task.FromResult(user.TwoFactorEnabled);
        }

        /// <summary>
        /// Sets whether two factor authentication is enabled for the user
        /// </summary>
        /// <param name="user">The identity user</param>
        /// <param name="enabled">True to enable two factoer</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a waitable servoce</returns>
        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            user.TwoFactorEnabled = enabled;

            return Task.FromResult(0);
        }

        /// <summary>
        /// Gets the phone number asynchronous.
        /// </summary>
        /// <param name="user">The identity user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Asynchronously returns the phone number for identity user</returns>
        public Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            return Task.FromResult(user.PhoneNumber);
        }

        /// <summary>
        /// Gets the phone number confirmed asynchronous.
        /// </summary>
        /// <param name="user">The identity user.</param>
        /// <returns>Returns a waitable task that waits on retrieving the phone confirmed</returns>
        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        /// <summary>
        /// Sets the phone number asynchronous.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="phoneNumber">The phone number.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a waitable task</returns>
        public Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));
            phoneNumber.NotNull(nameof(phoneNumber));

            user.PhoneNumber = phoneNumber;

            return Task.FromResult(0);
        }

        /// <summary>
        /// Sets the phone number confirmed .
        /// </summary>
        /// <param name="user">The identity user.</param>
        /// <param name="confirmed">if set to <c>true</c> [confirmed].</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns a waitable task</returns>
        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            user.PhoneNumberConfirmed = confirmed;

            return Task.FromResult(0);
        }

        /// <summary>
        /// Throws if disposed.
        /// </summary>
        /// <exception cref="System.ObjectDisposedException"></exception>
        private void ThrowIfDisposed()
        {
            if (_disposed) throw new ObjectDisposedException(GetType().Name);
        }

        /// <summary>
        /// Updates the user asynchronous.
        /// </summary>
        /// <param name="user">The identity user.</param>
        /// <returns>Returns a waitable task</returns>
        private async Task<IdentityResult> UpdateUserAsync(TUser user, CancellationToken token)
        {
            user.NotNull(nameof(user));
            user.Id.NotNullOrEmpty(nameof(user.Id), "Invalid user id");
            //user.Email.NotNullOrEmpty(nameof(user.Email), "Invalid email");
            //user.UserName.NotNullOrEmpty(nameof(user.UserName), "Invalid user name");

            user.Id = user?.Id?.ToLowerInvariant();
            //user.Email = user?.Email?.ToLowerInvariant();
            //user.UserName = user?.UserName?.ToLowerInvariant();


            try
            {
                token.ThrowIfCancellationRequested();
                //var response = await _client.UpsertDocumentAsync(_documentCollection, user, new RequestOptions { SessionToken = _feedOption.SessionToken });
                var response = await _client.ReplaceDocumentAsync(UriFactory.CreateDocumentUri(_database, _collection, user.Id), user, new RequestOptions { SessionToken = _feedOption.SessionToken });
                if (_feedOption.SessionToken == null) _feedOption.SessionToken = response.SessionToken;
                _user = user.Clone();
                return await Task.FromResult(IdentityResult.Success);
            }
            catch (DocumentClientException dce)
            {
                if (dce.StatusCode == System.Net.HttpStatusCode.NotFound) return await Task.FromResult(IdentityResult.Failed(new IdentityError { Code = "404", Description = "User not found" }));
                throw;
            }
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            //(_client as IDisposable)?.Dispose();
            _disposed = true;
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Gets the user id for the user
        /// </summary>
        /// <param name="user">User identity</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns the user id</returns>
        public Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            user.NotNull(nameof(user));

            return Task.FromResult(user.Id);
        }

        /// <summary>
        /// Gets the user name of the user identity
        /// </summary>
        /// <param name="user">User identity</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns the user name</returns>
        public Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            user.NotNull(nameof(user));

            return Task.FromResult(user.UserName);
        }

        /// <summary>
        /// Sets the user name for the user identity
        /// </summary>
        /// <param name="user">The user identity</param>
        /// <param name="userName">The user name</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns></returns>
        public Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            user.NotNull(nameof(user));
            userName.NotNullOrEmpty(nameof(userName), "Invalid user name");

            user.UserName = userName;
            return Task.FromResult(0);
        }

        /// <summary>
        /// Gets the normalized user name 
        /// </summary>
        /// <param name="user">The user identity</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns the normalized user name</returns>
        public virtual Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            return Task.FromResult(user.NormalizedUserName);
        }

        /// <summary>
        /// Sets the normalized user name
        /// </summary>
        /// <param name="user">The user identity</param>
        /// <param name="normalizedName"></param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Sets the normalized name to the user identity</returns>
        public virtual Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            user.NormalizedUserName = normalizedName;

            return Task.FromResult(0);
        }

        /// <summary>
        /// Gets the normalized email address for the user identity
        /// </summary>
        /// <param name="user"></param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Gets the normalized email address for the user identity</returns>
        public virtual Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            return Task.FromResult(user.NormalizedEmail);
        }

        /// <summary>
        /// Sets the normalized email address for the user
        /// </summary>
        /// <param name="user">The user identity
        /// <param name="normalizedEmail">The normalized email address</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Sets the normalized email address</returns>
        public virtual Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            user.NotNull(nameof(user));

            user.NormalizedEmail = normalizedEmail;

            return Task.FromResult(0);
        }


        /// <summary>
        /// Gets whether the user has confirmed phone number 
        /// </summary>
        /// <param name="user">The user identity</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken">cancellation token</see></param>
        /// <returns>Returns the flag indicating whether user has confirmed the phone number</returns>
        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            user.NotNull(nameof(user));

            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        /// <summary>
        /// 
        /// </summary>
        ~UserStore()
        {
            Dispose();
        }

        /// <summary>
        /// IQueryable identity user set
        /// </summary>
        public IQueryable<TUser> Users => _client.CreateDocumentQuery<TUser>(_documentCollection, new FeedOptions { EnableCrossPartitionQuery = true });
    }
}
