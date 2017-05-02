using Microsoft.Extensions.DependencyInjection;
using Simple.AspNetCore.Identity.DocumentDb;
using Simple.AspNetCore.Identity.DocumentDb.Models;
using System;

namespace Microsoft.AspNetCore.Identity
{
    /// <summary>
    /// Extension methods for the DocumentDb identity store
    /// </summary>
    public static class BuilderExtension
    {
        /// <summary>
        /// Adds the <see cref="Simple.AspNetCore.Identity.DocumentDb.DocumentDbOptions" /> to the DI container
        /// </summary>
        /// <param name="builder">ASP.NET Identity framework <see cref="IdentityBuilder"/></param>
        /// <param name="options"><see cref="DocumentDbOptions">Options</see> for DocumentDb identity store</param>
        /// <returns>Returns the <see cref="IdentityBuilder"/> instance</returns>
        public static IdentityBuilder AddDocumentDbOptions(this IdentityBuilder builder, DocumentDbOptions options)
        {
            builder.Services.AddSingleton<DocumentDbOptions>(options);
            builder.Services.AddScoped(typeof(IUserStore<>).MakeGenericType(builder.UserType), typeof(UserStore<>).MakeGenericType(builder.UserType));
            return builder;
        }

        /// <summary>
        /// Adds the <see cref="Simple.AspNetCore.Identity.DocumentDb.DocumentDbOptions" /> to the DI container
        /// </summary>
        /// <param name="builder">ASP.NET Identity framework <see cref="IdentityBuilder"/></param>
        /// <param name="optionsAccessor">Accessor to return the instance of the <see cref="DocumentDbOptions"/> for DocumentDb identity store</param>
        /// <returns>Returns the <see cref="IdentityBuilder"/> instance</returns>
        public static IdentityBuilder AddDocumentDbOptions(this IdentityBuilder builder, Func<IServiceProvider, DocumentDbOptions> optionsAccessor)
        {
            builder.Services.AddScoped<DocumentDbOptions>(optionsAccessor);
            builder.Services.AddScoped(typeof(IUserStore<>).MakeGenericType(builder.UserType), typeof(UserStore<>).MakeGenericType(builder.UserType));
            return builder;
        }
    }

    /*
    public interface IDocumentDbIdentityBuilder
    {
        /// <summary>
        /// Adds an <see cref="IUserStore{TUser}"/> for the <see cref="IdentityUser"/>. 
        /// </summary>
        /// <typeparam name="T">The identity user type who will be validated.</typeparam>
        /// <returns>The current <see cref="IDocumentDbIdentityBuilder{TUser}"/> instance.</returns>
        IdentityBuilder AddUserStore();
    }


    class DocumentDbIdentityBuilder: IDocumentDbIdentityBuilder //where TUser : IdentityUser
    {
        /// <summary>
        /// <see cref="IdentityBuilder"/> for the ASP.NET identity framework
        /// </summary>
        IdentityBuilder _builder;

        /// <summary>
        /// Create the instance of the <see cref="IDocumentDbIdentityBuilder"/> implementation
        /// </summary>
        /// <returns>Returns the <see cref="IdentityBuilder"/> instance</returns>
        public DocumentDbIdentityBuilder(IdentityBuilder builder)
        {
            builder.NotNull(nameof(builder));
            _builder = builder;
        }

        

        /// <summary>
        /// Adds an <see cref="IUserStore{TUser}"/> for the <see cref="IdentityUser"/>. 
        /// </summary>
        /// <typeparam name="T">The identity user type who will be validated.</typeparam>
        /// <returns>Returns the current <see cref="IDocumentDbIdentityBuilder{IdentityUser}"/> instance.</returns>
        IdentityBuilder IDocumentDbIdentityBuilder.AddUserStore() 
        {
            _builder.Services.AddScoped(typeof(IUserStore<>).MakeGenericType(_builder.UserType), typeof(UserStore<>).MakeGenericType(_builder.UserType));
            return _builder;
        }
    }
    */
}
