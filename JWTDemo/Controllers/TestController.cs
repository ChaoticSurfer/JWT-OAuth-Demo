using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {

            [HttpGet("TestAnonymous")]
            public IActionResult GetTestAnonymous()
            {
                return Ok("Hello Anonymous");
            }

            [HttpGet("TestAuthorize")]
            [Authorize]
            public IActionResult GetTestAuthorize()
            {
                return Ok("Hello Authorize");
            }
      }
}
