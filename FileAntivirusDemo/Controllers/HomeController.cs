using FileAntivirusDemo.Filter;
using Microsoft.AspNetCore.Mvc;

namespace FileAntivirusDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HomeController : ControllerBase
    {
        [HttpPost]
        [CheckFile]
        public async Task<IActionResult> UploadFile(IFormFile file)
        {
            return Ok(file.FileName);
        }
    }
}