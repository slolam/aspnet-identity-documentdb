using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Simple.AspNet.Identity.DocumentDb.Models
{
    /// <summary>
    /// Represents the claims of the identity
    /// </summary>
    public class IdentityUserClaim
    {
        /// <summary>
        /// Gets or sets the type of the claim.
        /// </summary>
        /// <value>The type of the claim.</value>
        public string Type { get; set; }

        /// <summary>
        /// Gets or sets the claim value.
        /// </summary>
        /// <value>The claim value.</value>
        public string Value { get; set; }

        /// <summary>
        /// Gets or sets the value type of the claim.
        /// </summary>
        public string ValueType { get; set; }

        /// <summary>
        /// Gets or sets the issuer of the claim.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the original issuer of the claim.
        /// </summary>
        public string OriginalIssuer { get; set; }
    }
}
