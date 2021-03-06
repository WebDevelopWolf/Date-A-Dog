using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AutoMapper;
using CloudinaryDotNet;
using CloudinaryDotNet.Actions;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Helpers;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace DatingApp.API.Controllers
{
    [Authorize]
    [Route("api/users/{userId}/photos")]
    [ApiController]
    public class PhotosController : ControllerBase
    {
        private readonly IDatingRepository _repo;
        private readonly IMapper _mapper;
        private readonly IOptions<CloudinarySettings> _cloudinaryConfig;
        private Cloudinary _cloudinary;

        public PhotosController(IDatingRepository repo, IMapper mapper, IOptions<CloudinarySettings> cloudinaryConfig)
        {
            _cloudinaryConfig = cloudinaryConfig;
            _mapper = mapper;
            _repo = repo;

            Account acc = new Account(
                _cloudinaryConfig.Value.CloudName,
                _cloudinaryConfig.Value.ApiKey,
                _cloudinaryConfig.Value.ApiSecret
            );

            _cloudinary = new Cloudinary(acc);
        }

        [HttpGet("{id}", Name = "GetPhoto")]
        public async Task<IActionResult> GetPhoto(int id) {
            var photoFromRepo = await _repo.GetPhoto(id);
            var photo = _mapper.Map<PhotoForReturnDto>(photoFromRepo);
            return Ok(photo);
        }

        [HttpPost]
        public async Task<IActionResult> AddPhotoForUser(int userId, [FromForm]PhotoForCreationDto photoForCreationDto) {
            // Check user is authorised
            if (userId != int.Parse(User.FindFirst(ClaimTypes.NameIdentifier).Value))
            {
                return Unauthorized();
            } 
            
            // Get current user
            var userFromRepo = await _repo.GetUser(userId);
            
            // Set up the file
            var file = photoForCreationDto.File;
            var uploadResult = new ImageUploadResult();
            // Check if we have a file...
            if (file.Length > 0)
            {
                // Start the upload
                using (var stream = file.OpenReadStream())
                {
                    // Set the upload parameters 
                    var uploadParams = new ImageUploadParams(){
                        // Create File
                        File = new FileDescription(file.Name, stream),
                        // Crop the Image to the users face
                        Transformation = new Transformation().Width(500).Height(500).Crop("fill").Gravity("face")
                    };
                    // Call the Cloudinary Upload Method
                    uploadResult = _cloudinary.Upload(uploadParams);
                }
            }

            // Set the Location and ID of the image
            photoForCreationDto.Url = uploadResult.Uri.ToString();
            photoForCreationDto.PublicId = uploadResult.PublicId;

            // Map the photo to the dto
            var photo = _mapper.Map<Photo>(photoForCreationDto);

            // If user does not have an images...
            if (!userFromRepo.Photos.Any(u => u.IsMain))
            {
                // Set photo as main image
                photo.IsMain = true;
            }

            // Add the image URL and ID to the database, save and return response
            userFromRepo.Photos.Add(photo);
            if (await _repo.SaveAll())
            {
                var photoToReturn = _mapper.Map<PhotoForReturnDto>(photo);
                return CreatedAtRoute("GetPhoto", new { userId = userId, id = photo.Id }, photoToReturn);
            }
            return BadRequest("Could not upload the photo");
        }

        [HttpPost("{id}/setMain")]
        public async Task<IActionResult> SetMainPhoto(int userId, int id) { 
            // Check user is authorised
            if (userId != int.Parse(User.FindFirst(ClaimTypes.NameIdentifier).Value))
            {
                return Unauthorized();
            } 
            
            // Get current user
            var user = await _repo.GetUser(userId);

            if (!user.Photos.Any(p => p.Id == id))
            {
                return Unauthorized();
            }

            // Get chosen photo
            var photoFromRepo = await _repo.GetPhoto(id);
            // Check if photo is already main photo
            if (photoFromRepo.IsMain)
            {
                return BadRequest("This is already the main photo");
            }

            // Get the current main photo and deselect it
            var currentMainPhoto = await _repo.GetMainPhotoForUser(userId);
            currentMainPhoto.IsMain = false;
            // Set the new photo as main
            photoFromRepo.IsMain = true;

            // Save and return
            if (await _repo.SaveAll())
            {
                return NoContent();
            }

            return BadRequest("Could not set photo to main");
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeletePhoto(int userId, int id) {
            // Check user is authorised
            if (userId != int.Parse(User.FindFirst(ClaimTypes.NameIdentifier).Value))
            {
                return Unauthorized();
            } 
            
            // Get current user
            var user = await _repo.GetUser(userId);

            if (!user.Photos.Any(p => p.Id == id))
            {
                return Unauthorized();
            }

            // Get chosen photo
            var photoFromRepo = await _repo.GetPhoto(id);
            
            // Check if photo is already main photo
            if (photoFromRepo.IsMain)
            {
                return BadRequest("You cannot delete your main photo");
            }

            if (photoFromRepo.PublicId != null)
            {
                 // Delete photo from Cloudinary
                var deleteParams = new DeletionParams(photoFromRepo.PublicId);
                var result = _cloudinary.Destroy(deleteParams);
                if (result.Result == "ok")
                {
                    // Delete photo from DB
                    _repo.Delete(photoFromRepo);
                }
            }

            if (photoFromRepo.PublicId == null)
            {
                // Delete photo from DB
                    _repo.Delete(photoFromRepo);
            }
           
            if (await _repo.SaveAll())
            {
                return Ok();
            }
            return BadRequest("Unable to delete photo");
        }
    }
}