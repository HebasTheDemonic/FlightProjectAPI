using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using FlightProject;
using FlightProject.Exceptions;
using FlightProject.Facades;
using FlightProject.POCOs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FlightProject_WebAPI.Controllers
{
    /// <summary>
    /// Controller for all Anonymous User Facade methods
    /// </summary>
    [Route("api/")]
    [ApiController]
    public class AnonymousFacadeController : ControllerBase
    {
        FlyingCenterSystem FlyingCenter = FlyingCenterSystem.GetInstance();
        AnonymousUserFacade AnonymousUserFacade = (AnonymousUserFacade)FlyingCenterSystem.FacadeList[0];
        readonly DateTime DEFAULT_DATE = new DateTime(1970, 01, 01);

        #region GET list of airline companies

        /// <summary>
        /// Get a list containing all registered airline companies.
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        [Produces(typeof(IList<AirlineCompany>))]
        [Route("airline/getall", Name = "GetAllCompanies")]
        [HttpGet]
        public IActionResult GetAllCompanies()
        {
            IActionResult result = SafeExecute(() =>
            {
                IList<AirlineCompany> companies = AnonymousUserFacade.GetAirlineCompanies();
                if (companies.Count < 1)
                {
                    return NoContent();
                }
                return Ok(companies);
            });
            return result;
        }
        #endregion

        #region Get All Countries

        /// <summary>
        /// Get a list of all registered countries
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        [Produces(typeof(IList<Country>))]
        [Route("country/getall", Name = "GetAllCountries")]
        [HttpGet]
        public IActionResult GetAllCountries()
        {
            IActionResult result = SafeExecute(() =>
            {
                IList<Country> countries = AnonymousUserFacade.GetAllCountries();
                if (countries.Count < 1)
                {
                    return NoContent();
                }
                return Ok(countries);
            });
            return result;
        }
        #endregion

        #region Get All Flights

        /// <summary>
        /// Get a list of all registered flights
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        [Produces(typeof(IList<Flight>))]
        [Route("flight/getall", Name = "GetAllFlights")]
        [HttpGet]
        public IActionResult GetAllFlights()
        {
            IActionResult result = SafeExecute(() =>
            {
                IList<Flight> flights = AnonymousUserFacade.GetAllFlights();
                if (flights.Count < 1)
                {
                    return NoContent();
                }
                return Ok(flights);
            });
            return result;
        }
        #endregion

        #region Get Country by ID
        /// <summary>
        /// Get a country by it's database ID
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="countryId"/>
        [Produces(typeof(Country))]
        [Route("country/getbyid", Name = "GetCountryById")]
        [HttpGet]
        public IActionResult GetCountryById([FromQuery]int countryId)
        {
            IActionResult result = SafeExecute(() =>
            {
                Country country = AnonymousUserFacade.GetCountryById(countryId);
                return SingleResultChecker(country, "No coutry with this ID was found.");
            });
            return result;
        }
        #endregion

        #region Get Flight by ID
        /// <summary>
        /// Get a Flight by it's database ID
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="flightId"/>
        [Produces(typeof(Flight))]
        [Route("flight/getbyid", Name = "GetFlightById")]
        [HttpGet]
        public IActionResult GetFlightById([FromQuery]int flightId)
        {
            IActionResult result = SafeExecute(() =>
            {
                Flight flight = AnonymousUserFacade.GetFlightById(flightId);
                return SingleResultChecker(flight, "No flight with this ID was found.");
            });
            return result;
        }
        #endregion

        #region Get Flight List by optional params
        /// <summary>
        /// Get a list of flights filtered by parameters.
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        [Produces(typeof(IList<Flight>))]
        [Route("flight/getbyparams", Name = "GetFlightByFilteredSearch")]
        [HttpGet]
        public IActionResult GetFlightByFilteredSearch([FromQuery]int originCountry = 0, [FromQuery]int destinationCountry = 0, [FromQuery]string departureDateString = "", [FromQuery]string landingDateString = "")
        {
            DateTime departureDate = DEFAULT_DATE;
            DateTime landingDate = DEFAULT_DATE;
            if (departureDateString != "")
            {
                departureDate = DateTime.Parse(departureDateString);
            }
            if (landingDateString != "")
            {
                landingDate = DateTime.Parse(landingDateString);
            }
            IActionResult result = SafeExecute(() =>
            {
                List<Flight> flights = (List<Flight>)AnonymousUserFacade.GetAllFlights();

                if (flights.Count > 0)
                {
                    if (originCountry != 0)
                    {
                        flights.RemoveAll(flight => flight.OriginCountryId != originCountry);
                    }
                    if (destinationCountry != 0)
                    {
                        flights.RemoveAll(flight => flight.DestinationCountryId != destinationCountry);
                    }
                    if (departureDate != DEFAULT_DATE)
                    {
                        flights.RemoveAll(flight => flight.DepartureTime.Date != departureDate.Date);
                    }
                    if (departureDate != DEFAULT_DATE)
                    {
                        flights.RemoveAll(flight => flight.LandingTime.Date != landingDate.Date);
                    }
                }

                if (flights.Count < 1)
                {
                    return NoContent();
                }
                return Ok(flights);
            });
            return result;
        }
        #endregion

        #region Create new customer
        /// <summary>
        /// Create a new customer
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="customer"/>
        [Produces(typeof(string))]
        [Route("customer/post/bycustomer", Name = "CreateCustomer")]
        [HttpPost]
        public IActionResult CreateCustomer([FromBody]Customer customer)
        {
            IActionResult result = SafeExecute(() =>
            {
                AnonymousUserFacade.CreateNewCustomer(customer);
                return Ok($"{customer.UserName} created succesfully.");
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
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (UserAlreadyExistsException ex)
            {
                return Conflict(ex.Message);
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