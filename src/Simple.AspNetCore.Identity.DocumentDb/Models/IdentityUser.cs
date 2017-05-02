using Microsoft.AspNetCore.Identity;
using Newtonsoft.Json;
using Simple.AspNetCore.Identity.DocumentDb;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace Simple.AspNetCore.Identity.DocumentDb.Models
{
    /// <summary>
    /// Represents identity user in the DocumentDb
    /// </summary>
    /// <seealso cref="Microsoft.AspNet.Identity.IUser" />
    public class IdentityUser 
    {
        /// <summary>
        /// Gets or sets the identifier of the user
        /// </summary>
        /// <value>
        /// The identifier.
        /// </value>
        [JsonProperty(PropertyName = "id")]
        public string Id { get; set; }

        /// <summary>
        /// Gets or sets the user name.
        /// </summary>
        /// <value>
        /// The user name of the user.
        /// </value>
        public virtual string UserName { get; set; }

        /// <summary>
        /// Gets or sets the user name.
        /// </summary>
        /// <value>
        /// The user name of the user.
        /// </value>
        internal string NormalizedUserName { get; set; }
        
        /// <summary>
        /// Gets or sets the email for the user
        /// </summary>
        /// <value>
        /// The email.
        /// </value>
        public virtual string Email { get; set; }

        /// <summary>
        /// Gets or sets the normalized email for the user
        /// </summary>
        /// <value>
        /// The email.
        /// </value>
        internal string NormalizedEmail { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether [email confirmed].
        /// </summary>
        /// <value>
        ///   <c>true</c> if [email confirmed]; otherwise, <c>false</c>.
        /// </value>
        public virtual bool EmailConfirmed { get; set; }

        /// <summary>
        /// Gets or sets the password hash.
        /// </summary>
        /// <value>
        /// The password hash.
        /// </value>
        public virtual string PasswordHash { get; set; }

        /// <summary>
        /// A random value that should change whenever a users credentials change (password changed, login removed)
        /// </summary>
        /// <value>
        /// The security stamp.
        /// </value>
        public virtual string SecurityStamp { get; set; }

        /// <summary>
        /// Gets or sets the phone number.
        /// </summary>
        /// <value>
        /// The phone number.
        /// </value>
        public virtual string PhoneNumber { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether [phone number confirmed].
        /// </summary>
        /// <value>
        /// <c>true</c> if [phone number confirmed]; otherwise, <c>false</c>.
        /// </value>
        public virtual bool PhoneNumberConfirmed { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether [two factor enabled].
        /// </summary>
        /// <value>
        ///   <c>true</c> if [two factor enabled]; otherwise, <c>false</c>.
        /// </value>
        public virtual bool TwoFactorEnabled { get; set; }

        /// <summary>
        /// Gets or sets the lockout end.
        /// </summary>
        /// <value>
        /// The lockout end.
        /// </value>
        [JsonConverter(typeof(EpochJsonConverter))]
        public virtual DateTimeOffset? LockoutEnd { get; set; }

        /// <summary>
        /// Gets or sets the last login at.
        /// </summary>
        /// <value>
        /// The last login at.
        /// </value>
        [JsonConverter(typeof(EpochJsonConverter))]
        public virtual DateTime LastLoginAt { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether [lockout enabled].
        /// </summary>
        /// <value>
        ///   <c>true</c> if [lockout enabled]; otherwise, <c>false</c>.
        /// </value>
        public virtual bool LockoutEnabled { get; set; }

        /// <summary>
        /// Gets or sets the access failed count.
        /// </summary>
        /// <value>
        /// The access failed count.
        /// </value>
        public virtual int AccessFailedCount { get; set; }

        /// <summary>
        /// Gets the logins.
        /// </summary>
        /// <value>
        /// The logins.
        /// </value>
        public virtual List<IdentityLoginInfo> Logins { get; private set; }

        /// <summary>
        /// Gets the claims.
        /// </summary>
        /// <value>
        /// The claims.
        /// </value>
        public virtual List<IdentityUserClaim> Claims { get; private set; }

        /// <summary>
        /// Gets the roles.
        /// </summary>
        /// <value>
        /// The roles.
        /// </value>
        public virtual List<string> Roles { get; private set; }

        /// <summary>
        /// Gets or sets the last updated at.
        /// </summary>
        /// <value>
        /// The last updated at.
        /// </value>
        [JsonProperty("_ts"), JsonConverter(typeof(EpochJsonConverter))]
        public DateTime LastUpdatedAt { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityUser"/> class.
        /// </summary>
        public IdentityUser()
        {
            Claims = new List<IdentityUserClaim>();
            Roles = new List<string>();
            Logins = new List<IdentityLoginInfo>();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityUser"/> class.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        public IdentityUser(string userName) : this()
        {
            UserName = userName;
        }

        //public bool ShouldSerializeLastUpdatedAt() => false;
    }
}
