using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace LetsEncrypt.Azure.Core.V2.DnsProviders
{
    public class DnsMadeEasyProvider : IDnsProvider
    {
        private readonly HttpClient httpClient;
        private DnsMadeEasySettings settings;
        private string domainId;
        private string recordId;

        public DnsMadeEasyProvider(DnsMadeEasySettings settings)
        {
            this.settings = settings;

            this.httpClient = new HttpClient();
            this.httpClient.BaseAddress = new Uri(settings.ApiBaseAddress);
        }

        public int MinimumTtl => 60;

        public async Task Cleanup(string recordSetName)
        {
            UpdateAuthHeaders();
            var result = await httpClient.DeleteAsync($"dns/managed/{domainId}/records/{recordId}");
            result.EnsureSuccessStatusCode();
        }

        public async Task PersistChallenge(string recordSetName, string recordValue)
        {
            UpdateAuthHeaders();
            var result = await httpClient.GetAsync($"dns/managed/name?domainname={this.settings.Domain}");
            result.EnsureSuccessStatusCode();
            
            JObject record = JsonConvert.DeserializeObject<JObject>(await result.Content.ReadAsStringAsync());
            domainId = record["id"].ToString();

            UpdateAuthHeaders();
            var txtResult = await httpClient.GetAsync($"dns/managed/{domainId}/records?recordName={recordSetName}&type=TXT");
            txtResult.EnsureSuccessStatusCode();

            JObject txtRecord = JsonConvert.DeserializeObject<JObject>(await txtResult.Content.ReadAsStringAsync());
            var totalRecords = (int)txtRecord["totalRecords"];

            HttpResponseMessage updateRes = null;

            var acmeChallengeRecord = new DnsRecord {
                value = recordValue,
                name = recordSetName,
                ttl = MinimumTtl,
                type = "TXT"
            };

            UpdateAuthHeaders();
            
            if (totalRecords == 0) {
                updateRes = await this.httpClient.PostAsync(
                    $"dns/managed/{domainId}/records/", 
                    new StringContent(JsonConvert.SerializeObject(acmeChallengeRecord), Encoding.UTF8, "application/json")
                );
            } else {
                this.recordId = txtRecord["data"][0]["id"].ToString();
                acmeChallengeRecord.id = this.recordId;

                updateRes = await this.httpClient.PutAsync(
                    $"dns/managed/{domainId}/records/{recordId}", 
                    new StringContent(JsonConvert.SerializeObject(acmeChallengeRecord), Encoding.UTF8, "application/json")
                );
            }

            updateRes.EnsureSuccessStatusCode();
        }

        private void UpdateAuthHeaders() {
            this.httpClient.DefaultRequestHeaders.Clear();
            
            var date = DateTime.UtcNow.ToString("r");
            var hash = new HMACSHA1(Encoding.ASCII.GetBytes(this.settings.ApiSecret));
            var hmac = hash.ComputeHash(Encoding.ASCII.GetBytes(date));
            var hexDigest = BitConverter.ToString(hmac).Replace("-", "").ToLower();
            
            this.httpClient.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "application/json");
            this.httpClient.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/json");
            this.httpClient.DefaultRequestHeaders.TryAddWithoutValidation("x-dnsme-apiKey", this.settings.ApiKey);
            this.httpClient.DefaultRequestHeaders.TryAddWithoutValidation("x-dnsme-requestDate", date);
            this.httpClient.DefaultRequestHeaders.TryAddWithoutValidation("x-dnsme-hmac", hexDigest);
        }

        private class DnsRecord
        {
            public string value { get; set; }
            public string name { get; set; }
            public int ttl { get; set; }
            public string type { get; set; }
            public string id { get; set; }
        }

    }

    public class DnsMadeEasySettings
    {
        public string ApiKey { get; set; }
        public string ApiSecret { get; set; }
        public string Domain { get; set; }
        public string ApiBaseAddress { get; set; }
    }
}
