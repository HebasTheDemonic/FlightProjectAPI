using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.POCOs;
using FlightProject.Exceptions;
using System.Data.SqlClient;

namespace FlightProject.Facades
{
    public class LoggedInAdministratorFacade : AnonymousUserFacade, ILoggedInAdministratorFacade
    {
        public new LoginToken<Administrator> LoginToken { get; }

        internal LoggedInAdministratorFacade(LoginToken<Administrator> token)
        {
            LoginToken = token;
            _administratorDAO = new DAOs.AdministratorDAO();
            _airlineDAO = new DAOs.AirlineDAO();
            _customerDAO = new DAOs.CustomerDAO();
            _flightDAO = new DAOs.FlightDAO();
            _ticketDAO = new DAOs.TicketDAO();
            _customerDAO = new DAOs.CustomerDAO();
            _generalDAO = new DAOs.GeneralDAO();
            _countryDAO = new DAOs.CountryDAO();
        }

        public void CreateNewAdministrator(LoginToken<Administrator> token, Administrator administrator)
        {
            if (token.CheckToken())
            {
                if (token.User.UserName.ToUpper() == "ADMIN")
                {
                    if (_generalDAO.DoesUsernameExist(administrator.UserName) == 0)
                    {
                        if (_administratorDAO.DoesAdministratorExist(administrator) == 0)
                        {
                            _administratorDAO.Add(administrator);
                            return;
                        }
                    }
                    throw new UserAlreadyExistsException();
                }
                else
                {
                    throw new UnauthorizedActionException($"Administrator {token.User.UserName} is not allowed to add new administrators");
                }
            }
        }

        public void CreateNewAirline(LoginToken<Administrator> token, AirlineCompany airline)
        {
            if (token.CheckToken())
            {
                if (_generalDAO.DoesUsernameExist(airline.UserName) == 0)
                {
                    if (_airlineDAO.DoesAirlineCompanyExist(airline) == 0)
                    {
                        _airlineDAO.Add(airline);
                        return;
                    }
                }
                throw new UserAlreadyExistsException();
            }
        }

        public void CreateNewCustomer(LoginToken<Administrator> token, Customer customer)
        {
            if (token.CheckToken())
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
        }

        public void RemoveAdministrator(LoginToken<Administrator> token, Administrator administrator)
        {
            if (administrator.UserName.ToUpper() == "ADMIN")
            {
                throw new UnauthorizedActionException("Cannot remove master administrator account.");
            }
            if (token.CheckToken())
            {
                if (administrator.UserName == token.User.UserName)
                {
                    throw new UnauthorizedActionException("Cannot remove own account.");
                }
                administrator = _administratorDAO.GetAdministratorByUsername(administrator.UserName);
                _administratorDAO.Remove(administrator);
            }

        }

        public void RemoveAirline(LoginToken<Administrator> token, AirlineCompany airline)
        {
            if (token.CheckToken())
            {
                if (_airlineDAO.DoesAirlineCompanyExist(airline) == 1)
                {
                    airline = _airlineDAO.GetAirlineCompanybyUsername(airline.UserName);
                    List<Flight> flights = (List<Flight>)_flightDAO.GetFlightsByAirlineCompany(airline);
                    foreach (Flight flight in flights)
                    {
                        List<Ticket> tickets = (List<Ticket>)_ticketDAO.GetAllTicketsByFlight(flight.Id);
                        foreach (Ticket ticket in tickets)
                        {
                            _ticketDAO.Remove(ticket);
                        }
                        _flightDAO.Remove(flight);
                    }
                    _airlineDAO.Remove(airline);
                }
                else
                {
                    throw new UserNotFoundException("Airline does not exist");
                }
            }
        }

        public void RemoveCustomer(LoginToken<Administrator> token, Customer customer)
        {
            if (token.CheckToken())
            {
                if (_customerDAO.DoesCustomerExist(customer) == 1)
                {
                    customer = _customerDAO.GetCustomerByUsername(customer.UserName);
                    List<Ticket> tickets = (List<Ticket>)_ticketDAO.GetAllTicketsByCustomer(customer);
                    foreach (Ticket ticket in tickets)
                    {
                        _ticketDAO.Remove(ticket);
                    }
                    _customerDAO.Remove(customer);
                }
                else
                {
                    throw new UserNotFoundException("Customer does not exist");
                }
            }
        }

        public void UpdateAdministrator(LoginToken<Administrator> token, Administrator administrator)
        {
            if (token.CheckToken())
            {
                if (token.User.UserName.ToUpper() == "ADMIN")
                {
                    try
                    {
                        Administrator tempAdministrator = _administratorDAO.GetAdministratorByUsername(administrator.UserName);
                        if (tempAdministrator.UserName == null)
                        {
                            throw new Exception();
                        }
                        administrator = new Administrator(tempAdministrator.Id, administrator.UserName, administrator.Password);
                    }
                    catch (Exception)
                    {
                        throw new UnauthorizedActionException("Usernames cannot be changed.");
                    }
                    _administratorDAO.Update(administrator);
                }
                else
                {
                    throw new UnauthorizedActionException("Only head administrator can change administrator accounts.");
                }
            }
        }

        public void UpdateAirlineDetails(LoginToken<Administrator> token, AirlineCompany airline)
        {
            if (token.CheckToken())
            {
                try
                {
                    AirlineCompany airlineCompany = _airlineDAO.GetAirlineCompanybyUsername(airline.UserName);
                    if (airlineCompany.UserName == null)
                    {
                        throw new Exception();
                    }
                    airline = new AirlineCompany(airlineCompany.Id, airline.AirlineName, airline.UserName, airline.Password, airline.OriginCountry);
                }
                catch (Exception)
                {
                    throw new UnauthorizedActionException("Usernames cannot be changed.");
                }
                _airlineDAO.Update(airline);
            }
        }

        public void UpdateCustomerDetails(LoginToken<Administrator> token, Customer customer)
        {
            if (token.CheckToken())
            {
                try
                {
                    Customer tempCustomer = _customerDAO.GetCustomerByUsername(customer.UserName);
                    if (tempCustomer.UserName == null)
                    {
                        throw new Exception();
                    }
                    customer = new Customer(tempCustomer.Id, customer.FirstName, customer.LastName, customer.UserName, customer.Password, customer.Address, customer.PhoneNo, customer.CreditCardNumber);
                }
                catch (Exception)
                {
                    throw new UnauthorizedActionException("Usernames cannot be changed.");
                }
                _customerDAO.Update(customer);
            }
        }

        public void CreateCountry(LoginToken<Administrator> token, Country country)
        {
            if (token.CheckToken())
            {
                try
                {
                    _countryDAO.Add(country);
                }
                catch (Exception)
                {
                    throw;
                }
            }
        }

        public void UpdateCountry(LoginToken<Administrator> token, Country country)
        {
            if (token.CheckToken())
            {
                if (country.ID != 0)
                {
                    _countryDAO.Update(country);
                }
                else
                {
                    throw new UnregisteredDataException();
                }
            }
        }

        public void RemoveCountry(LoginToken<Administrator> token, Country country)
        {
            if (token.CheckToken())
            {
                if (country.ID != 0)
                {
                    _countryDAO.Remove(country);
                }
                else
                {
                    throw new UnregisteredDataException();
                }
            }
        }
    }
}
