using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using BnBTechnologies.Xrm.Tourism.WebAPI;
using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Client;
using Microsoft.Xrm.Sdk.Query;

namespace SurveyWebAPI.Controllers
{
    public class SurveyController : ApiController
    {
        public struct Survey
        {
            public string bnb_name;
            public Guid bnb_surveyid;
        }
        [HttpGet]
        public IHttpActionResult GetSurvey(Guid id)
        {
            Survey _survey;

            //connect to CRM
            OrganizationServiceProxy _serviceProxy;
            ServerConnection _serverConnection;

            ServerConnection connection = new ServerConnection();
            if (!connection.ReadConfigurations())
            {
                connection.GetServerConfiguration();
                connection.SaveConfiguration(@"Credentials.xml", connection.configurations[0], false);
            }

            _serverConnection = connection;

            using (_serviceProxy = new OrganizationServiceProxy(
                _serverConnection.configurations[0].OrganizationUri,
                _serverConnection.configurations[0].HomeRealmUri,
                _serverConnection.configurations[0].Credentials,
                _serverConnection.configurations[0].Credentials
                ))
            {
                Entity entity = _serviceProxy.Retrieve("bnb_survey", id, new ColumnSet("bnb_name"));
                _survey.bnb_name = entity.Attributes["bnb_name"].ToString();
                _survey.bnb_surveyid = (Guid)entity.Attributes["bnb_surveyid"];
            }

            return Ok(_survey);
        }

        [HttpGet]
        public IHttpActionResult GetAllSurveys()
        {
            List<Survey> _survey = new List<Survey>();

            //connect to CRM
            OrganizationServiceProxy _serviceProxy;
            ServerConnection _serverConnection;

            ServerConnection connection = new ServerConnection();
            if (!connection.ReadConfigurations())
            {
                connection.GetServerConfiguration();
                connection.SaveConfiguration(@"Credentials.xml", connection.configurations[0], false);
            }

            _serverConnection = connection;

            using (_serviceProxy = new OrganizationServiceProxy(
                _serverConnection.configurations[0].OrganizationUri,
                _serverConnection.configurations[0].HomeRealmUri,
                _serverConnection.configurations[0].Credentials,
                _serverConnection.configurations[0].Credentials
                ))
            {
                EntityCollection entityColl = _serviceProxy.RetrieveMultiple(new QueryExpression("bnb_survey")
                {
                    ColumnSet = new ColumnSet(new String[] { "bnb_surveyid", "bnb_name" }),
                    Criteria = new FilterExpression()
                    {
                        Conditions = {
                            new ConditionExpression(){
                                AttributeName = "statecode",
                                Operator = ConditionOperator.Equal,
                                Values = {
                                    0
                                }
                            }

                        }
                    }
                });

                foreach (Entity entity in entityColl.Entities)
                {
                    Survey __survey;
                    __survey.bnb_name = entity.Attributes["bnb_name"].ToString();
                    __survey.bnb_surveyid = (Guid)entity.Attributes["bnb_surveyid"];

                    _survey.Add(__survey);
                }
            }

            return Ok(_survey);
        }

        // POST api/values
        public void Post([FromBody]string value)
        {
        }

        // PUT api/values/5
        public void Put(int id, [FromBody]string value)
        {
        }

        // DELETE api/values/5
        public void Delete(int id)
        {
        }
    }
}
