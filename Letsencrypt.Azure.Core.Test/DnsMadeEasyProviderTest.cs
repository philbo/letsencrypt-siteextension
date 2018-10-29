using LetsEncrypt.Azure.Core.V2;
using LetsEncrypt.Azure.Core.V2.DnsProviders;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using static LetsEncrypt.Azure.Core.V2.DnsProviders.DnsMadeEasyProvider;

namespace Letsencrypt.Azure.Core.Test
{
    [TestClass]
    public class DnsMadeEasyProviderTest
    {
        public IConfiguration Configuration { get; }
        public DnsMadeEasyProvider DnsService { get; }

        public DnsMadeEasyProviderTest()
        {
            this.Configuration = new ConfigurationBuilder()            
                .AddUserSecrets<DnsMadeEasyProviderTest>()
                .Build();

            this.DnsService = new DnsMadeEasyProvider(new DnsMadeEasySettings()
            {
                ApiKey = this.Configuration["ApiKey"],
                ApiSecret = this.Configuration["ApiSecret"],
                ApiBaseAddress = this.Configuration["ApiBaseAddress"],
                Domain = this.Configuration["Domain"]
            });
        }

        [TestMethod]
        public async Task TestPersistChallengeCreatesNewRecord()
        {
            var id = Guid.NewGuid().ToString();
            await DnsService.PersistChallenge("_acme-challenge", id);

            var exists = await new DnsLookupService().Exists("*." + this.Configuration["Domain"], id);
            Assert.IsTrue(exists);

            await DnsService.Cleanup("_acme-challenge");
        }


        [TestMethod]
        public async Task TestPersistChallengeUpdatesExistingRecord()
        {
            var id = Guid.NewGuid().ToString();
            await DnsService.PersistChallenge("_acme-challenge", id);
            await DnsService.PersistChallenge("_acme-challenge", id);

            var exists = await new DnsLookupService().Exists("*." + this.Configuration["Domain"], id);
            Assert.IsTrue(exists);

            await DnsService.Cleanup("_acme-challenge");
        }
    }
}
