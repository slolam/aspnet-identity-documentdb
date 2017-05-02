using System;
using System.Collections.Generic;
using System.Text;

namespace Simple.AspNetCore.Identity.DocumentDb.Models
{
    /// <summary>
    /// Represents login information and source for a user record.
    /// </summary>
    public class IdentityLoginInfo
    {
        /// <summary>
        /// Gets or sets the provider for this instance of Microsoft.AspNetCore.Identity.UserLoginInfo.
        /// </summary>
        /// <remarks>Examples of the provider may be Local, Facebook, Google, etc.</remarks>
        public string LoginProvider { get; set; }
        /// <summary>
        /// Gets or sets the unique identifier for the user identity user provided by the
        ///     login provider.
        /// </summary>
        /// <remarks>This would be unique per provider, examples may be @microsoft as a Twitter provider key.</remarks>
        public string ProviderKey { get; set; }
    }
}
