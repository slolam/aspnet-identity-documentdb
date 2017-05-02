using Newtonsoft.Json;
using Simple.AspNet.Identity.DocumentDb.Models;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Simple.AspNet.Identity.DocumentDb
{
    static class Extentions
    {

        /// <summary>
        /// Nots the null.
        /// </summary>
        /// <param name="thisObject">The this object.</param>
        /// <param name="paramName">Name of the parameter.</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void NotNull(this object thisObject, string paramName)
        {
            if (thisObject == null) throw new ArgumentNullException(paramName);
        }

        /// <summary>
        /// Nots the null or empty.
        /// </summary>
        /// <param name="thisString">The this string.</param>
        /// <param name="paramName">Name of the parameter.</param>
        /// <param name="message">The message.</param>
        /// <exception cref="ArgumentException"></exception>
        public static void NotNullOrEmpty(this string thisString, string paramName, string message)
        {
            if (string.IsNullOrEmpty(thisString)) throw new ArgumentException(message, paramName);
        }

        /// <summary>
        /// Clones the specified this object.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="thisObject">The this object.</param>
        /// <returns></returns>
        public static T Clone<T>(this T thisObject) where T: class
        {
            if (thisObject == null) return null;
            return JsonConvert.DeserializeObject<T>(JsonConvert.SerializeObject(thisObject));
        }

        private static DateTime Date19700101 = new DateTime(1970, 1, 1);
        /// <summary>
        /// To the epoch.
        /// </summary>
        /// <param name="date">The date.</param>
        /// <returns></returns>
        public static int ToEpoch(this DateTime date)
        {
            if (date < Date19700101)
                return int.MinValue;

            return (int)(date - Date19700101).TotalSeconds;
        }


        /// <summary>
        /// Converts the <see cref="IdentityUserClaim"/> to <see cref="Claim"/>
        /// </summary>
        /// <param name="thisClaim">The <see cref="IdentityUserClaim"/> to be converted</param>
        /// <returns>Returns the newly created <see cref="Claim"/></returns>
        public static Claim ToClaim(this IdentityUserClaim thisClaim)
        {
            return new Claim(thisClaim.Type, thisClaim.Value, thisClaim.ValueType, thisClaim.Issuer, thisClaim.OriginalIssuer);
        }


        /// <summary>
        /// Converts the <see cref="Claim"/> to <see cref="IdentityUserClaim"/>
        /// </summary>
        /// <param name="thisClaim">The <see cref="IdentityUserClaim"/> to be converted</param>
        /// <returns>Returns the newly created <see cref="IdentityUserClaim"/></returns>
        public static IdentityUserClaim ToClaim(this Claim thisClaim)
        {
            return new IdentityUserClaim
            {
                Type = thisClaim.Type,
                Value = thisClaim.Value,
                ValueType = thisClaim.ValueType,
                Issuer = thisClaim.Issuer,
                OriginalIssuer = thisClaim.OriginalIssuer
            };
        }
    }

}
