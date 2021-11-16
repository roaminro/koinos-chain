#pragma once

#include <koinos/state_db/backends/backend.hpp>
#include <koinos/state_db/backends/map/map_iterator.hpp>

namespace koinos::state_db::backends::map {

class map_backend final : public abstract_backend {
   public:
      using key_type   = abstract_backend::key_type;
      using value_type = abstract_backend::value_type;
      using size_type  = abstract_backend::size_type;

      map_backend();
      virtual ~map_backend();

      // Iterators
      virtual iterator begin();
      virtual iterator end();

      // Modifiers
      virtual void put( const key_type& k, const value_type& v );
      virtual void erase( const key_type& k );
      virtual void clear();

      virtual size_type size()const;

      // Lookup
      virtual iterator find( const key_type& k );
      virtual iterator lower_bound( const key_type& k );

   private:
      std::map< key_type, value_type > _map;
};

} // koinos::state_db::backends::map