using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;
using System.Web.Http.Routing;

namespace SurveyWebAPI
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services

            // Web API routes
            config.MapHttpAttributeRoutes();


            // define route
            IHttpRoute defaultRoute = config.Routes.CreateRoute("api/{controller}/{action}/{id}",
                                                new { id = RouteParameter.Optional }, null);

            config.Routes.Add("DefaultApi", defaultRoute);
        }
    }
}
