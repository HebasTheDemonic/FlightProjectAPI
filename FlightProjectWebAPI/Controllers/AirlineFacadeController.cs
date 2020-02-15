using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;
using FlightProject;
using FlightProject.Exceptions;
using FlightProject.Facades;
using FlightProject.POCOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FlightProject_WebAPI.Controllers
{
    [Route("api/")]
    [ApiController]
    [Authorize(Roles = "AirlineCompany")]
    public class AirlineFacadeController : ControllerBase
    {
        #region Get tickets by flight
        /// <summary>
        /// Get a list of all tickets that were purchased for a flight
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="flightId"/>
        [Produces(typeof(IList<Ticket>))]
        [Route("ticket/getbyflight", Name = "GetTicketsByFlight")]
        [HttpGet]
        public IActionResult GetTicketsByFlight(int flightId)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAirlineFacade airlineFacade = (LoggedInAirlineFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                List<Ticket> tickets = (List<Ticket>)airlineFacade.GetAllTicketsByFlight(airlineFacade.LoginToken, flightId);
                if (tickets.Count < 1)
                {
                    return NoContent();
                }
                return Ok(tickets);
            });
            return result;
        }
        #endregion

        #region Get flights of airline
        /// <summary>
        /// Get a list of all flight made by current airline
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        [Produces(typeof(IList<Flight>))]
        [Route("flight/getbyairline", Name = "GetFlightsByAirline")]
        [HttpGet]
        public IActionResult GetFlightsByAirline()
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAirlineFacade airlineFacade = (LoggedInAirlineFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                List<Flight> flights = (List<Flight>)airlineFacade.GetAllFlightsByAirline(airlineFacade.LoginToken);
                if (flights.Count < 1)
                {
                    return NoContent();
                }
                return Ok(flights);
            });
            return result;
        }
        #endregion

        #region Delete flight
        /// <summary>
        /// Delete an existing flight
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="flightId"/>
        [Produces(typeof(string))]
        [Route("flight/delete", Name = "DeleteFlight")]
        [HttpDelete]
        public IActionResult DeleteFlight([FromQuery]int flightId)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAirlineFacade airlineFacade = (LoggedInAirlineFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                airlineFacade.CancelFlight(airlineFacade.LoginToken, flightId);
                return Ok();
            });
            return result;
        }
        #endregion

        #region Create flight
        /// <summary>
        /// Delete an existing flight
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// 
        [Produces(typeof(string))]
        [Route("flight/post", Name = "CreateFlight")]
        [HttpPost]
        public IActionResult CreateFlight([FromBody]Flight flight)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAirlineFacade airlineFacade = (LoggedInAirlineFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                airlineFacade.CreateFlight(airlineFacade.LoginToken, flight);
                return Ok();
            });
            return result;
        }
        #endregion

        #region Update flight
        /// <summary>
        /// Delete an existing flight
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        ///
        [Produces(typeof(string))]
        [Route("flight/put", Name = "UpdateFlight")]
        [HttpPost]
        public IActionResult UpdateFlight([FromBody]Flight flight)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAirlineFacade airlineFacade = (LoggedInAirlineFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                airlineFacade.UpdateFlight(airlineFacade.LoginToken, flight.Id, flight);
                return Ok();
            });
            return result;
        }
        #endregion

        #region Change airline password
        /// <summary>
        /// Delete an existing flight
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// 
        [Produces(typeof(string))]
        [Route("airline/put/byairline/password", Name = "ChangeAirlinePassword")]
        [HttpPut]
        public IActionResult ChangePassword([FromQuery]string oldPassword, [FromQuery]string newPassword)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAirlineFacade airlineFacade = (LoggedInAirlineFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                airlineFacade.ChangeMyPassword(airlineFacade.LoginToken, oldPassword, newPassword);
                if (airlineFacade.LoginToken.User.Password != newPassword)
                {
                    return new StatusCodeResult(StatusCodes.Status304NotModified);
                }
                return Ok();
            });
            return result;
        }
        #endregion

        #region Update airline details
        /// <summary>
        /// Delete an existing flight
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// 
        [Produces(typeof(string))]
        [Route("airline/put/byairline/details", Name = "ChangeDetails")]
        [HttpPut]
        public IActionResult ChangeDetails([FromBody]AirlineCompany airlineCompany)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAirlineFacade airlineFacade = (LoggedInAirlineFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                airlineFacade.ModifyAirlineDetails(airlineFacade.LoginToken, airlineCompany);
                if (airlineFacade.LoginToken.User != airlineCompany)
                {
                    return new StatusCodeResult(StatusCodes.Status304NotModified);
                }
                return Ok();
            });
            return result;
        }
        #endregion


        #region SafeExecute Method
        /// <summary>
        /// A method for all general try-catch instances
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="func"/>
        private IActionResult SafeExecute(Func<IActionResult> func)
        {
            try
            {
                return func.Invoke();
            }
            catch (NullReferenceException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (UnauthorizedActionException ex)
            {
                return Conflict(ex.Message);
            }
            catch (WrongPasswordException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (DataAlreadyExistsException ex)
            {
                return Conflict(ex.Message);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (SqlException)
            {
                return new StatusCodeResult(StatusCodes.Status503ServiceUnavailable);
            }
            catch (Exception)
            {
                return new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }
        }
        #endregion

        #region RetreiveFacadeIndex Method
        /// <summary>
        /// A method for extracting the correct facade index for the current user
        /// </summary>
        /// <returns>
        /// int
        /// </returns>
        private int RetriveFacadeIndex()
        {
            string indexString = HttpContext.User.Claims.Where(c => c.Type.ToString().Equals("FacadeListLocation")).ToString();
            int facadeIndex = Int32.Parse(indexString);
            return facadeIndex;
        }
        #endregion

        #region SingleResultChecker Method
        /// <summary>
        /// A method meant to verify a non-null response to non list result queries
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="poco"/>
        /// <param name="nullResponce"/>
        private IActionResult SingleResultChecker(IPoco poco, string nullResponce)
        {
            IActionResult result;
            if (poco.GetHashCode() == 0)
            {
                result = BadRequest(nullResponce);
            }
            else
            {
                result = Ok(poco);
            }
            return result;
        }
        #endregion
    }
}