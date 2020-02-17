using FlightProject.Exceptions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightProject.POCOs
{
    public class AirlineCompany : User, IPoco
    {
        public int Id { get; }
        public string AirlineName { get; }
        public int OriginCountry { get; }

        public AirlineCompany()
        {

        }

        public AirlineCompany(string username, string password) : base(username,password)
        {

        }

        public AirlineCompany(string airlineName, string username, string password, int originCountry) : this(username, password)
        {
            AirlineName = airlineName ?? throw new ArgumentNullException(nameof(airlineName));
            OriginCountry = originCountry;
        }

        internal AirlineCompany(int id, string airlineName, string username, string password, int originCountry) : this(airlineName, username, password, originCountry)
        {
            Id = id;
        }

        public static bool operator ==(AirlineCompany airlineCompany1, AirlineCompany airlineCompany2) => airlineCompany1.Equals(airlineCompany2);


        public static bool operator !=(AirlineCompany airlineCompany1, AirlineCompany airlineCompany2) => !(airlineCompany1 == airlineCompany2);

        public override bool Equals(object obj)
        {
            var company = obj as AirlineCompany;
            if (Username == null || company.Username == null)
            {
                throw new CorruptedDataException();
            }
            return company != null &&
                   Username == company.Username;
        }

        public override int GetHashCode()
        {
            return 2000000 + Id.GetHashCode();
        }
    }
}
