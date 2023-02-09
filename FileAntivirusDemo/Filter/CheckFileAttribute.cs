using FileAntivirusDemo.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;
using nClam;

namespace FileAntivirusDemo.Filter
{
    public class CheckFileAttribute : TypeFilterAttribute
    {
        /// <summary>
        ///
        /// </summary>
        /// <param name="maxFileSize">Defaul Max 10 mb </param>
        public CheckFileAttribute(int maxFileSize = 10485760) : base(typeof(CheckFileActionFilter))
        {
            Arguments = new object[] { maxFileSize };
        }

        public class CheckFileActionFilter : IAsyncActionFilter
        {
            private readonly ClamAVServer _clamAVServer;
            private readonly int _maxFileSize;

            public CheckFileActionFilter(int maxFileSize, IOptions<ClamAVServer> options)
            {
                _maxFileSize = maxFileSize;
                _clamAVServer = options.Value;
            }

            public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
            {
                IFormFileCollection formFiles = context.HttpContext.Request.Form.Files;

                foreach (var formFile in formFiles)
                {
                    if (formFile == null)
                        throw new ArgumentNullException("context", "null");

                    if (formFile.Length >= _maxFileSize)
                        throw new ArgumentOutOfRangeException("context", "MaxFileSize");

                    var ms = new MemoryStream();
                    formFile.OpenReadStream().CopyTo(ms);
                    byte[] fileBytes = ms.ToArray();

                    var clam = new ClamClient(_clamAVServer.Url, _clamAVServer.Port);
                    var scanResult = await clam.SendAndScanFileAsync(fileBytes);

                    bool isClamAVAvailible = await clam.TryPingAsync();

                    if (isClamAVAvailible)
                    {
                        switch (scanResult.Result)
                        {
                            case ClamScanResults.Clean:
                                await next();
                                break;

                            case ClamScanResults.VirusDetected: //exception firlat
                                throw new ArgumentException("context", "Virus Detected");
                            case ClamScanResults.Error:
                                throw new ArgumentException("context", "Error in File");
                            case ClamScanResults.Unknown:
                                throw new ArgumentException("context", "Unknown File");
                        }
                    }
                    else
                    {
                        throw new ArgumentException("context", "ClamAV is not installed on this server.");
                    }
                }
            }
        }
    }
}