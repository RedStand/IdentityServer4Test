﻿// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;

namespace Idp
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> Ids =>
            new IdentityResource[]
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Address(),
                new IdentityResources.Phone(),
                new IdentityResources.Email()
            };


        public static IEnumerable<ApiResource> Apis =>
            new ApiResource[]
            {
                new ApiResource("api1", "My API #1")
            };


        public static IEnumerable<Client> Clients =>
            new Client[]
            {
                new Client
                {
                    ClientId = "console client",
                    ClientName = "Client Credentials Client",
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    ClientSecrets = {new Secret("511536EF-F270-4058-80CA-1C89C192F69A".Sha256())},
                    AllowedScopes = {"api1" , IdentityServerConstants.StandardScopes.OpenId}
                } ,
                new Client{

                    ClientId = "wpf client",
                    AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
                    ClientSecrets =
                    {
                        new Secret("wpf secrect".Sha256())
                    },
                    AllowedScopes = {"api1" ,
                        IdentityServerConstants.StandardScopes.OpenId ,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Address,
                        IdentityServerConstants.StandardScopes.Email ,
                        IdentityServerConstants.StandardScopes.Phone
                    }
                },
                new Client{ 
                    ClientId = "mvc client",
                    ClientName = "ASP.Net Core MVC Client",
                    AllowedGrantTypes = GrantTypes.CodeAndClientCredentials,
                    ClientSecrets = { new Secret ("mvc secret".Sha256()) },
                    RedirectUris = { "http://localhost:5002/signin-oidc"},
                    FrontChannelLogoutUri =  "http://localhost:5002/signout-oidc",
                    PostLogoutRedirectUris = {"http://localhost:5002/signout-callback-oidc"},
                    AlwaysIncludeUserClaimsInIdToken = true,
                    AllowOfflineAccess = true , 
                    AccessTokenLifetime = 60,
                    AllowedScopes =
                    {                      
                        "api1",
                        IdentityServerConstants.StandardScopes.OpenId ,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Address,
                        IdentityServerConstants.StandardScopes.Email ,
                        IdentityServerConstants.StandardScopes.Phone
                    }

                }

            };
    }
}