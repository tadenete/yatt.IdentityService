namespace yatt.IdentityService.Helpers;

using AutoMapper;
using yatt.IdentityService.Entities;
using yatt.IdentityService.Models;

public class AutoMapperProfile : Profile
{
    public AutoMapperProfile()
    {
        CreateMap<RegisterRequest, User>();
        CreateMap<User, UserResponse>()
            .ForMember(dest => dest.Role, opt => opt.MapFrom(opt => Convert.ToString(opt.Role)))
            .ForMember(dest => dest.Organizations,
                 opt => opt.MapFrom(
                     opt => (opt.UserOrganizations == null ? null : opt.UserOrganizations.Select(x => x.OrganizationId).ToList())
                 ));
    }
}