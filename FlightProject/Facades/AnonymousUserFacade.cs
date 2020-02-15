using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.POCOs;
using FlightProject.DAOs;
using FlightProject.Exceptions;
using System.Data.SqlClient;

namespace FlightProject.Facades
{
    public class AnonymousUserFacade : FacadeBase, IAnonymousUserFacade
    {

        public LoginToken<User> LoginToken { get; }

        internal AnonymousUserFacade()
        {
            LoginToken = null;
            _airlineDAO = new AirlineDAO();
            _flightDAO = new FlightDAO();
            _countryDAO = new CountryDAO();
        }

        public void CreateNewCustomer(Customer customer)
        {
            if (_generalDAO.DoesUsernameExist(customer.UserName) == 0)
            {
                if (_customerDAO.DoesCustomerExist(customer) == 0)
                {
                    _customerDAO.Add(customer);
                    return;
                }
            }
            throw new UserAlreadyExistsException();
        }

        // Returns a list of all airline companies if there is atleast one company in the database.
        // If an SQL error is cought throws it up

        public IList<AirlineCompany> GetAirlineCompanies()
        {
            try
            {
                List<AirlineCompany> airlineCompanies = (List<AirlineCompany>)_airlineDAO.GetAll();
                return airlineCompanies;
            }
            catch (SqlException)
            {
                throw;
            }
        }

        public IList<Country> GetAllCountries()
        {
            List<Country> countries = (List<Country>)_countryDAO.GetAll();
            return countries;
        }

        // Returns a list of all flights if there is atleast one in the database.
        // If an SQL error is cought throws it up

        public IList<Flight> GetAllFlights()
        {
            try
            {
                List<Flight> flights = (List<Flight>)_flightDAO.GetAll();
                return flights;
            }
            catch (SqlException)
            {
                throw;
            }
        }

        public Country GetCountryById(int id)
        {
            Country country = _countryDAO.Get(id);
            return country;
        }

        // Returns data on a single flight that corresponds to the requested ID.
        // If returned object is null catches and incapsules it in NullResultException.
        // If an SQL error is cought throws it up

        public Flight GetFlightById(int id)
        {
            try
            {
                Flight flight = _flightDAO.Get(id);
                if (flight.Id == 0)
                {
                    throw new NullReferenceException();
                }
                return flight;
            }
            catch (NullReferenceException dataEx)
            {
                throw new NullResultException("No flight with this ID was found", dataEx);
            }
            catch (SqlException)
            {
                throw;
            }
        }

        // Returns a list of flights taking off on provided date if any exist.
        // If an SQL error is cought throws it up

        public IList<Flight> GetFlightsByDepartureDate(DateTime departureDate)
        {
            try
            {
                List<Flight> flightsDepartingOnDate = (List<Flight>)_flightDAO.GetFlightsByDepartureDate(departureDate);
                return flightsDepartingOnDate;
            }
            catch (SqlException)
            {
                throw;
            }
        }

        // Returns a list of flights landing in country if any exist.
        // If an SQL error is cought throws it up

        public IList<Flight> GetFlightsByDestinationCountry(int CountryCode)
        {
            try
            {
                List<Flight> flightsLandingInCountry = (List<Flight>)_flightDAO.GetFlightsByDestinationCountry(CountryCode);
                return flightsLandingInCountry;
            }
            catch (SqlException)
            {
                throw;
            }
        }

        // Returns a list of flights landing on provided date if any exist.
        // If an SQL error is cought throws it up

        public IList<Flight> GetFlightsByLandingDate(DateTime landingTime)
        {
            try
            {
                List<Flight> flightsLandingOnDate = (List<Flight>)_flightDAO.GetFlightsByLandingDate(landingTime);
                return flightsLandingOnDate;
            }
            catch (SqlException)
            {
                throw;
            }
        }

        // Returns a list of flights taking off from country if any exist.
        // If an SQL error is cought throws it up

        public IList<Flight> GetFlightsByOriginCountry(int CountryCode)
        {
            try
            {
                List<Flight> flightsDepartingFromCountry = (List<Flight>)_flightDAO.GetFlightsByOriginCountry(CountryCode);
                return flightsDepartingFromCountry;
            }
            catch (SqlException)
            {
                throw;
            }
        }
    }
}
