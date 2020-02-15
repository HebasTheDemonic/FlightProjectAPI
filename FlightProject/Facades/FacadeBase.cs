using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.DAOs;

namespace FlightProject.Facades
{
    public abstract class FacadeBase
    {
        internal IAdministratorDAO _administratorDAO;
        internal IAirlineDAO _airlineDAO;
        internal ICountryDAO _countryDAO;
        internal ICustomerDAO _customerDAO;
        internal IFlightDAO _flightDAO;
        internal ITicketDAO _ticketDAO;
        internal IGeneralDAO _generalDAO;

        protected FacadeBase()
        {

        }
    }
}
